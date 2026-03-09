# Copyright (c) 2026 mogaqu
"""Модуль проверки прав администратора с кэшированием.

Requirement 4.5: Non-admin users cannot use moderation commands
Кэширование статуса админа на 5 минут для оптимизации.
"""
import time
from typing import Dict, Optional, Tuple
from telegram import ChatMember, Update
from telegram.error import TelegramError
from telegram.ext import ContextTypes
from telegram.constants import ChatType

from app.logging_config import log
from app.security.data_protection import pseudonymize_id, pseudonymize_chat_id
from app import config
import secrets


# Кэш статуса админа: {(chat_id, user_id): (is_admin, timestamp)}
_admin_cache: Dict[Tuple[int, int], Tuple[bool, float]] = {}

# Время жизни кэша в секундах (5 минут)
ADMIN_CACHE_TTL = 300


def _is_cache_valid(timestamp: float) -> bool:
    """Проверить, не истёк ли кэш."""
    return time.time() - timestamp < ADMIN_CACHE_TTL


def clear_admin_cache(chat_id: Optional[int] = None, user_id: Optional[int] = None) -> int:
    """Очистить кэш статуса админа.
    
    Args:
        chat_id: Если указан, очистить только для этого чата
        user_id: Если указан, очистить только для этого пользователя
        
    Returns:
        Количество удалённых записей
    """
    global _admin_cache
    
    if chat_id is None and user_id is None:
        count = len(_admin_cache)
        _admin_cache = {}
        return count
    
    keys_to_remove = []
    for key in _admin_cache:
        c_id, u_id = key
        if chat_id is not None and c_id != chat_id:
            continue
        if user_id is not None and u_id != user_id:
            continue
        keys_to_remove.append(key)
    
    for key in keys_to_remove:
        del _admin_cache[key]
    
    return len(keys_to_remove)


def invalidate_admin_cache(chat_id: int, user_id: int) -> None:
    """Инвалидировать кэш для конкретного пользователя в чате."""
    key = (chat_id, user_id)
    _admin_cache.pop(key, None)


def get_cached_admin_status(chat_id: int, user_id: int) -> Optional[bool]:
    """Получить закэшированный статус админа.
    
    Returns:
        True/False если есть валидный кэш, None если кэш отсутствует или истёк
    """
    key = (chat_id, user_id)
    cached = _admin_cache.get(key)
    
    if cached is None:
        return None
    
    is_admin, timestamp = cached
    if not _is_cache_valid(timestamp):
        del _admin_cache[key]
        return None
    
    return is_admin


def set_cached_admin_status(chat_id: int, user_id: int, is_admin: bool) -> None:
    """Установить статус админа в кэш."""
    key = (chat_id, user_id)
    _admin_cache[key] = (is_admin, time.time())


async def check_admin_permission(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    send_error_message: bool = True
) -> bool:
    """Проверить, является ли пользователь админом чата.
    
    Requirement 4.5: Non-admin users cannot use moderation commands
    
    Использует кэширование на 5 минут для оптимизации.
    
    Args:
        update: Telegram Update
        context: Контекст бота
        send_error_message: Отправлять ли сообщение об ошибке
        
    Returns:
        True если пользователь админ чата или бот-админ, False иначе
    """
    if not update.message or not update.effective_chat or not update.effective_user:
        return False
    
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    # Проверяем, является ли пользователь глобальным админом бота
    if config.ADMIN_ID and secrets.compare_digest(str(user_id), str(config.ADMIN_ID)):
        return True
    
    # В приватных чатах команды модерации не работают
    if update.message.chat.type == ChatType.PRIVATE:
        if send_error_message:
            await update.message.reply_text("⚠️ Команды модерации работают только в группах.")
        return False
    
    # Проверяем кэш
    cached_status = get_cached_admin_status(chat_id, user_id)
    if cached_status is not None:
        if not cached_status and send_error_message:
            await update.message.reply_text("⚠️ Эта команда доступна только администраторам чата.")
        return cached_status
    
    # Запрашиваем статус через API
    try:
        member = await context.bot.get_chat_member(chat_id, user_id)
        is_admin = member.status in (ChatMember.ADMINISTRATOR, ChatMember.OWNER)
        
        # Кэшируем результат
        set_cached_admin_status(chat_id, user_id, is_admin)
        
        if not is_admin and send_error_message:
            await update.message.reply_text("⚠️ Эта команда доступна только администраторам чата.")
        
        return is_admin
        
    except TelegramError as exc:
        log.error(f"Ошибка проверки статуса админа для {pseudonymize_id(user_id)} в чате {pseudonymize_chat_id(chat_id)}: {exc}")
        
        if send_error_message:
            await update.message.reply_text("⚠️ Не удалось проверить права администратора.")
        
        return False


async def is_user_admin(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    user_id: int
) -> bool:
    """Проверить, является ли пользователь админом чата (без Update).
    
    Args:
        context: Контекст бота
        chat_id: ID чата
        user_id: ID пользователя
        
    Returns:
        True если пользователь админ, False иначе
    """
    # Проверяем глобального админа бота
    if config.ADMIN_ID and secrets.compare_digest(str(user_id), str(config.ADMIN_ID)):
        return True
    
    # Проверяем кэш
    cached_status = get_cached_admin_status(chat_id, user_id)
    if cached_status is not None:
        return cached_status
    
    # Запрашиваем через API
    try:
        member = await context.bot.get_chat_member(chat_id, user_id)
        is_admin = member.status in (ChatMember.ADMINISTRATOR, ChatMember.OWNER)
        
        # Кэшируем
        set_cached_admin_status(chat_id, user_id, is_admin)
        
        return is_admin
        
    except TelegramError as exc:
        log.error(f"Ошибка проверки статуса админа для {pseudonymize_id(user_id)} в чате {pseudonymize_chat_id(chat_id)}: {exc}")
        return False


def cleanup_expired_cache() -> int:
    """Очистить истёкшие записи из кэша.
    
    Returns:
        Количество удалённых записей
    """
    global _admin_cache
    
    current_time = time.time()
    keys_to_remove = [
        key for key, (_, timestamp) in _admin_cache.items()
        if current_time - timestamp >= ADMIN_CACHE_TTL
    ]
    
    for key in keys_to_remove:
        del _admin_cache[key]
    
    return len(keys_to_remove)
