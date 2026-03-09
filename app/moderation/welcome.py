# Copyright (c) 2026 mogaqu
"""Система приветствий для новых участников чата.

Requirements:
- 1.1: Send customizable welcome message within 3 seconds
- 1.2: Support placeholders {username}, {chatname}, {membercount}
- 1.4: Send welcome message only once if user joins multiple times within 1 hour
"""
import asyncio
import html
from typing import Optional

from telegram import Bot, Chat, User
from telegram.constants import ParseMode
from telegram.error import TelegramError

from app.logging_config import log
from app.security.data_protection import pseudonymize_id, pseudonymize_chat_id
from app.moderation.models import ChatModSettings
from app.moderation.storage import redis_client

# Redis key prefix for join event deduplication
JOIN_CACHE_PREFIX = "welcome_join:"
# TTL for join cache entries (1 hour = 3600 seconds)
JOIN_CACHE_TTL_SEC = 3600


class WelcomeManager:
    """Менеджер приветственных сообщений.
    
    Requirement 1.1: Send customizable welcome message within 3 seconds
    Requirement 1.2: Support placeholders {username}, {chatname}, {membercount}
    Requirement 1.4: Deduplication - send welcome only once per hour per user
    """
    
    def __init__(self, bot: Bot):
        self.bot = bot
    
    def format_template(
        self,
        template: str,
        user: User,
        chat: Chat,
        member_count: Optional[int] = None
    ) -> str:
        """Форматирует шаблон приветствия с подстановкой плейсхолдеров.
        
        Requirement 1.2: Support placeholders {username}, {chatname}, {membercount}
        
        Args:
            template: Шаблон сообщения с плейсхолдерами
            user: Пользователь для подстановки
            chat: Чат для подстановки
            member_count: Количество участников (опционально)
            
        Returns:
            Отформатированное сообщение с HTML-экранированием
        """
        # Получаем username или имя пользователя
        username = user.username
        if username:
            username_display = f"@{username}"
        else:
            # Используем имя если нет username
            username_display = user.first_name or "Участник"
        
        # Экранируем HTML для безопасности
        username_safe = html.escape(username_display)
        chatname_safe = html.escape(chat.title or "Чат")
        membercount_str = str(member_count) if member_count is not None else "?"
        
        # Подставляем плейсхолдеры
        result = template
        result = result.replace("{username}", username_safe)
        result = result.replace("{chatname}", chatname_safe)
        result = result.replace("{membercount}", membercount_str)
        
        return result
    
    def _get_join_cache_key(self, chat_id: int, user_id: int) -> str:
        """Получить ключ Redis для кэша join-событий."""
        return f"{JOIN_CACHE_PREFIX}{chat_id}:{user_id}"
    
    def check_already_welcomed(self, chat_id: int, user_id: int) -> bool:
        """Проверить, было ли уже отправлено приветствие пользователю.
        
        Requirement 1.4: Check if user was already welcomed within 1 hour
        
        Returns:
            True если приветствие уже было отправлено, False иначе
        """
        key = self._get_join_cache_key(chat_id, user_id)
        try:
            return redis_client.exists(key) > 0
        except Exception as exc:
            log.error(f"Ошибка проверки кэша приветствий: {exc}")
            # В случае ошибки Redis разрешаем отправку
            return False
    
    def mark_welcomed(self, chat_id: int, user_id: int) -> None:
        """Отметить, что пользователю было отправлено приветствие.
        
        Requirement 1.4: Mark user as welcomed with 1 hour TTL
        """
        key = self._get_join_cache_key(chat_id, user_id)
        try:
            redis_client.setex(key, JOIN_CACHE_TTL_SEC, "1")
        except Exception as exc:
            log.error(f"Ошибка записи в кэш приветствий: {exc}")
    
    async def send_welcome(
        self,
        chat_id: int,
        user: User,
        chat: Chat,
        settings: ChatModSettings
    ) -> bool:
        """Отправить приветственное сообщение новому участнику.
        
        Requirement 1.1: Send customizable welcome message within 3 seconds
        Requirement 1.3: Respect welcome_enabled setting
        Requirement 1.4: Deduplication - don't send if already welcomed within 1 hour
        
        Args:
            chat_id: ID чата
            user: Новый участник
            chat: Объект чата
            settings: Настройки модерации чата
            
        Returns:
            True если сообщение было отправлено, False иначе
        """
        # Проверяем, включены ли приветствия
        if not settings.welcome_enabled:
            return False
        
        # Проверяем дедупликацию (Requirement 1.4)
        if self.check_already_welcomed(chat_id, user.id):
            log.debug(f"Пользователь {user.id} уже был приветствован в чате {chat_id}")
            return False
        
        # Получаем количество участников для плейсхолдера
        member_count: Optional[int] = None
        try:
            member_count = await self.bot.get_chat_member_count(chat_id)
        except TelegramError as exc:
            log.warning(f"Не удалось получить количество участников чата {pseudonymize_chat_id(chat_id)}: {exc}")
        
        # Форматируем сообщение
        message_text = self.format_template(
            settings.welcome_message,
            user,
            chat,
            member_count
        )
        
        # Применяем задержку если настроена (Requirement 7.5)
        if settings.welcome_delay_sec > 0:
            await asyncio.sleep(settings.welcome_delay_sec)
        
        # Отправляем сообщение
        try:
            if settings.welcome_private:
                # Отправляем в личку пользователю
                sent_message = await self.bot.send_message(
                    chat_id=user.id,
                    text=message_text,
                    parse_mode=ParseMode.HTML
                )
            else:
                # Отправляем в чат
                sent_message = await self.bot.send_message(
                    chat_id=chat_id,
                    text=message_text,
                    parse_mode=ParseMode.HTML
                )
            
            # Отмечаем что приветствие отправлено
            self.mark_welcomed(chat_id, user.id)
            
            # Автоудаление если настроено (Requirement 7.5)
            if settings.welcome_auto_delete_sec > 0 and not settings.welcome_private:
                asyncio.create_task(
                    self._auto_delete_message(
                        chat_id,
                        sent_message.message_id,
                        settings.welcome_auto_delete_sec
                    )
                )
            
            log.info(f"Приветствие отправлено пользователю {pseudonymize_id(user.id)} в чате {pseudonymize_chat_id(chat_id)}")
            return True
            
        except TelegramError as exc:
            log.error(f"Ошибка отправки приветствия в чат {pseudonymize_chat_id(chat_id)}: {exc}")
            return False
    
    async def _auto_delete_message(
        self,
        chat_id: int,
        message_id: int,
        delay_sec: int
    ) -> None:
        """Автоматически удалить сообщение после задержки."""
        try:
            await asyncio.sleep(delay_sec)
            await self.bot.delete_message(chat_id=chat_id, message_id=message_id)
            log.debug(f"Автоудаление приветствия {message_id} в чате {chat_id}")
        except TelegramError as exc:
            log.warning(f"Не удалось удалить приветствие {message_id}: {exc}")
        except asyncio.CancelledError:
            pass


# Вспомогательные функции для использования без создания экземпляра класса

def format_welcome_message(
    template: str,
    user: User,
    chat: Chat,
    member_count: Optional[int] = None
) -> str:
    """Форматирует шаблон приветствия с подстановкой плейсхолдеров.
    
    Standalone функция для использования без WelcomeManager.
    """
    # Получаем username или имя пользователя
    username = user.username
    if username:
        username_display = f"@{username}"
    else:
        username_display = user.first_name or "Участник"
    
    # Экранируем HTML для безопасности
    username_safe = html.escape(username_display)
    chatname_safe = html.escape(chat.title or "Чат")
    membercount_str = str(member_count) if member_count is not None else "?"
    
    # Подставляем плейсхолдеры
    result = template
    result = result.replace("{username}", username_safe)
    result = result.replace("{chatname}", chatname_safe)
    result = result.replace("{membercount}", membercount_str)
    
    return result


def check_user_welcomed(chat_id: int, user_id: int) -> bool:
    """Проверить, было ли уже отправлено приветствие пользователю.
    
    Standalone функция для использования без WelcomeManager.
    """
    key = f"{JOIN_CACHE_PREFIX}{chat_id}:{user_id}"
    try:
        return redis_client.exists(key) > 0
    except Exception as exc:
        log.error(f"Ошибка проверки кэша приветствий: {exc}")
        return False


def mark_user_welcomed(chat_id: int, user_id: int) -> None:
    """Отметить, что пользователю было отправлено приветствие.
    
    Standalone функция для использования без WelcomeManager.
    """
    key = f"{JOIN_CACHE_PREFIX}{chat_id}:{user_id}"
    try:
        redis_client.setex(key, JOIN_CACHE_TTL_SEC, "1")
    except Exception as exc:
        log.error(f"Ошибка записи в кэш приветствий: {exc}")
