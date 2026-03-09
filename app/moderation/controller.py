# Copyright (c) 2026 mogaqu
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List

from telegram import Bot, Chat, Message, User
from telegram.constants import ChatType
from telegram.error import TelegramError

from app.logging_config import log
from app.security.data_protection import pseudonymize_id, pseudonymize_chat_id
from app.moderation.models import ChatModSettings, ModAction, Warn
from app.moderation.storage import (
    load_settings,
    load_settings_async,
    save_settings,
    save_settings_async,
    save_mod_action_async,
)
from app.moderation.spam import SpamFilter, SpamAction, SpamCheckResult, get_spam_reason_message
from app.moderation.warns import WarnSystem, WarnResult, WarnEscalation
from app.moderation.content_filter import ContentFilter, FilterCheckResult
from app.moderation.captcha import CaptchaManager, CaptchaProvider
from app.moderation.welcome import WelcomeManager
from app.moderation.logger import ModLogger, log_mod_action


class ModerationAction(str, Enum):
    """Типы действий модерации."""
    NONE = "none"
    DELETE = "delete"
    WARN = "warn"
    MUTE = "mute"
    BAN = "ban"
    KICK = "kick"
    HOLD = "hold"


@dataclass
class ModerationResult:
    """Результат проверки модерации."""
    action: ModerationAction
    reason: str
    should_delete_message: bool = False
    mute_duration_min: int = 0
    warn_count: int = 0
    details: Optional[str] = None


class ModerationController:
    """Центральный контроллер модерации.
    
    Объединяет все компоненты модерации и предоставляет
    единую точку входа для обработки событий.
    """
    
    def __init__(self, bot: Bot):
        """Инициализация контроллера.
        
        Args:
            bot: Telegram Bot instance
        """
        self.bot = bot
        self._settings_cache: dict[int, ChatModSettings] = {}
    
    # ========================================================================
    # SETTINGS MANAGEMENT
    # ========================================================================
    
    def get_settings(self, chat_id: int) -> ChatModSettings:
        """Получить настройки модерации для чата (синхронно).
        
        Args:
            chat_id: ID чата
            
        Returns:
            ChatModSettings для чата
        """
        if chat_id not in self._settings_cache:
            self._settings_cache[chat_id] = load_settings(chat_id)
        return self._settings_cache[chat_id]
    
    async def get_settings_async(self, chat_id: int) -> ChatModSettings:
        """Получить настройки модерации для чата (асинхронно).
        
        Args:
            chat_id: ID чата
            
        Returns:
            ChatModSettings для чата
        """
        if chat_id not in self._settings_cache:
            self._settings_cache[chat_id] = await load_settings_async(chat_id)
        return self._settings_cache[chat_id]
    
    def invalidate_settings_cache(self, chat_id: int) -> None:
        """Инвалидировать кэш настроек для чата."""
        self._settings_cache.pop(chat_id, None)
    
    async def update_settings(self, settings: ChatModSettings) -> None:
        """Обновить настройки модерации.
        
        Args:
            settings: Новые настройки
        """
        await save_settings_async(settings)
        self._settings_cache[settings.chat_id] = settings
    
    # ========================================================================
    # USER JOIN HANDLING (Requirements 1, 2.3, 6)
    # ========================================================================
    
    async def on_user_join(
        self,
        chat_id: int,
        user: User,
        chat: Chat
    ) -> None:
        """Обработка входа нового пользователя.
        
        Requirements:
        - 1.1: Send customizable welcome message within 3 seconds
        - 2.3: Record join time for newbie link filter
        - 6.1: Send captcha challenge when captcha is enabled
        - 6.3: Grant full chat permissions and send welcome message on captcha success
        - 6.4: Allow immediate participation when captcha is disabled
        
        Args:
            chat_id: ID чата
            user: Новый участник
            chat: Объект чата
        """
        # Пропускаем ботов
        if user.is_bot:
            return
        
        settings = await self.get_settings_async(chat_id)
        
        # Записываем время входа для фильтра ссылок новичков (Requirement 2.3)
        from app.moderation.spam import record_user_join_async
        await record_user_join_async(chat_id, user.id)
        
        # Проверяем, включена ли captcha (Requirement 6.1, 6.4)
        if settings.captcha_enabled:
            # Отправляем captcha challenge
            captcha_manager = CaptchaManager(self.bot, settings)
            await captcha_manager.create_captcha(
                chat_id=chat_id,
                user=user,
                settings=settings
            )
        else:
            # Captcha выключена - сразу отправляем приветствие (Requirement 6.4)
            if settings.welcome_enabled:
                welcome_manager = WelcomeManager(self.bot)
                await welcome_manager.send_welcome(
                    chat_id=chat_id,
                    user=user,
                    chat=chat,
                    settings=settings
                )
    
    # ========================================================================
    # MESSAGE CHECKING (Requirements 2, 5)
    # ========================================================================
    
    async def on_message(
        self,
        chat_id: int,
        user: User,
        message: Message,
        text: str
    ) -> ModerationResult:
        """Проверка сообщения на спам и фильтры.
        
        Requirements:
        - 2.1: Mute user for 5 minutes if they send more than 5 messages within 10 seconds
        - 2.2: Delete messages with known spam patterns
        - 2.3: Hold messages with links from newbies
        - 5.1: Automatically delete messages containing blacklisted words
        
        Args:
            chat_id: ID чата
            user: Автор сообщения
            message: Объект сообщения
            text: Текст сообщения
            
        Returns:
            ModerationResult с действием и причиной
        """
        settings = await self.get_settings_async(chat_id)
        timestamp = time.time()
        
        # Проверка контент-фильтра (Requirement 5.1)
        if settings.filter_words:
            content_filter = ContentFilter(settings)
            filter_result = content_filter.check(text)
            
            if filter_result.is_filtered:
                return ModerationResult(
                    action=ModerationAction.DELETE,
                    reason=f"filter:{filter_result.matched_word}",
                    should_delete_message=True,
                    details=f"Сообщение содержит запрещённое слово: {filter_result.matched_word}"
                )
        
        # Проверка спама (Requirements 2.1, 2.2, 2.3)
        if settings.spam_enabled or settings.link_filter_enabled:
            spam_filter = SpamFilter(settings)
            spam_result = await spam_filter.check_message(
                user_id=user.id,
                text=text,
                message_id=message.message_id,
                timestamp=timestamp
            )
            
            if spam_result.action != SpamAction.NONE:
                action_map = {
                    SpamAction.MUTE: ModerationAction.MUTE,
                    SpamAction.DELETE: ModerationAction.DELETE,
                    SpamAction.WARN: ModerationAction.WARN,
                    SpamAction.HOLD: ModerationAction.HOLD,
                }
                
                return ModerationResult(
                    action=action_map.get(spam_result.action, ModerationAction.NONE),
                    reason=spam_result.reason,
                    should_delete_message=spam_result.should_delete,
                    mute_duration_min=spam_result.mute_duration_min,
                    details=get_spam_reason_message(spam_result.reason)
                )
        
        return ModerationResult(action=ModerationAction.NONE, reason="")
    
    # ========================================================================
    # WARN SYSTEM (Requirement 3)
    # ========================================================================
    
    async def add_warn(
        self,
        chat_id: int,
        user_id: int,
        admin_id: int,
        reason: str
    ) -> WarnResult:
        """Добавить предупреждение пользователю.
        
        Requirement 3.1: Record warning with reason, timestamp, and issuing admin
        Requirement 3.2: Auto-mute after warn_mute_threshold
        Requirement 3.3: Auto-ban after warn_ban_threshold
        
        Args:
            chat_id: ID чата
            user_id: ID пользователя
            admin_id: ID админа
            reason: Причина предупреждения
            
        Returns:
            WarnResult с информацией о предупреждении и эскалации
        """
        settings = await self.get_settings_async(chat_id)
        warn_system = WarnSystem(settings)
        result = await warn_system.add_warn_async(chat_id, user_id, admin_id, reason)
        
        # Логируем действие
        await log_mod_action(
            bot=self.bot,
            chat_id=chat_id,
            action_type="warn",
            target_user_id=user_id,
            reason=reason,
            admin_id=admin_id,
            auto=False
        )
        
        return result
    
    async def get_warns(self, chat_id: int, user_id: int) -> List[Warn]:
        """Получить все предупреждения пользователя.
        
        Requirement 3.4: Display all warnings for that user with dates and reasons
        """
        warn_system = WarnSystem()
        return await warn_system.get_warns_async(chat_id, user_id)
    
    async def clear_warns(self, chat_id: int, user_id: int, admin_id: int) -> int:
        """Очистить все предупреждения пользователя.
        
        Requirement 3.5: Remove all warnings for that user
        """
        warn_system = WarnSystem()
        count = await warn_system.clear_warns_async(chat_id, user_id)
        
        if count > 0:
            # Логируем действие
            await log_mod_action(
                bot=self.bot,
                chat_id=chat_id,
                action_type="clearwarns",
                target_user_id=user_id,
                reason=f"Очищено {count} предупреждений",
                admin_id=admin_id,
                auto=False
            )
        
        return count
    
    # ========================================================================
    # MODERATION COMMANDS (Requirement 4)
    # ========================================================================
    
    async def ban_user(
        self,
        chat_id: int,
        user_id: int,
        admin_id: int,
        reason: str
    ) -> bool:
        """Забанить пользователя.
        
        Requirement 4.1: Permanently ban the user and log the action
        """
        try:
            await self.bot.ban_chat_member(chat_id=chat_id, user_id=user_id)
            
            await log_mod_action(
                bot=self.bot,
                chat_id=chat_id,
                action_type="ban",
                target_user_id=user_id,
                reason=reason,
                admin_id=admin_id,
                auto=False
            )
            
            return True
        except TelegramError as exc:
            log.error(f"Не удалось забанить пользователя {pseudonymize_id(user_id)}: {exc}")
            return False
    
    async def mute_user(
        self,
        chat_id: int,
        user_id: int,
        admin_id: Optional[int],
        reason: str,
        duration_min: int,
        auto: bool = False
    ) -> bool:
        """Замутить пользователя.
        
        Requirement 4.2: Restrict the user from sending messages for the specified duration
        """
        try:
            until_date = int(time.time()) + (duration_min * 60)
            await self.bot.restrict_chat_member(
                chat_id=chat_id,
                user_id=user_id,
                permissions={"can_send_messages": False},
                until_date=until_date
            )
            
            await log_mod_action(
                bot=self.bot,
                chat_id=chat_id,
                action_type="mute",
                target_user_id=user_id,
                reason=f"{reason} ({duration_min} мин)",
                admin_id=admin_id,
                auto=auto
            )
            
            return True
        except TelegramError as exc:
            log.error(f"Не удалось замутить пользователя {pseudonymize_id(user_id)}: {exc}")
            return False
    
    async def unmute_user(
        self,
        chat_id: int,
        user_id: int,
        admin_id: int
    ) -> bool:
        """Размутить пользователя.
        
        Requirement 4.3: Restore the user's messaging permissions
        """
        try:
            # Получаем дефолтные права чата
            chat = await self.bot.get_chat(chat_id)
            default_permissions = chat.permissions
            
            await self.bot.restrict_chat_member(
                chat_id=chat_id,
                user_id=user_id,
                permissions=default_permissions
            )
            
            await log_mod_action(
                bot=self.bot,
                chat_id=chat_id,
                action_type="unmute",
                target_user_id=user_id,
                reason="Размут",
                admin_id=admin_id,
                auto=False
            )
            
            return True
        except TelegramError as exc:
            log.error(f"Не удалось размутить пользователя {pseudonymize_id(user_id)}: {exc}")
            return False
    
    async def kick_user(
        self,
        chat_id: int,
        user_id: int,
        admin_id: int,
        reason: str
    ) -> bool:
        """Кикнуть пользователя (без бана).
        
        Requirement 4.4: Remove the user from chat without banning
        """
        try:
            # Баним и сразу разбаниваем
            await self.bot.ban_chat_member(chat_id=chat_id, user_id=user_id)
            await self.bot.unban_chat_member(chat_id=chat_id, user_id=user_id)
            
            await log_mod_action(
                bot=self.bot,
                chat_id=chat_id,
                action_type="kick",
                target_user_id=user_id,
                reason=reason,
                admin_id=admin_id,
                auto=False
            )
            
            return True
        except TelegramError as exc:
            log.error(f"Не удалось кикнуть пользователя {pseudonymize_id(user_id)}: {exc}")
            return False
    
    # ========================================================================
    # CONTENT FILTER (Requirement 5)
    # ========================================================================
    
    async def add_filter_word(self, chat_id: int, word: str) -> bool:
        """Добавить слово в фильтр.
        
        Requirement 5.1: Add word to blacklist via /addfilter
        """
        settings = await self.get_settings_async(chat_id)
        content_filter = ContentFilter(settings)
        result = content_filter.add_word(word)
        
        if result:
            self.invalidate_settings_cache(chat_id)
        
        return result
    
    async def remove_filter_word(self, chat_id: int, word: str) -> bool:
        """Удалить слово из фильтра.
        
        Requirement 5.4: Remove word from blacklist via /removefilter
        """
        settings = await self.get_settings_async(chat_id)
        content_filter = ContentFilter(settings)
        result = content_filter.remove_word(word)
        
        if result:
            self.invalidate_settings_cache(chat_id)
        
        return result
    
    def get_filter_words(self, chat_id: int) -> List[str]:
        """Получить список слов в фильтре.
        
        Requirement 5.3: Display all active filters
        """
        settings = self.get_settings(chat_id)
        return list(settings.filter_words)
    
    # ========================================================================
    # CAPTCHA (Requirement 6)
    # ========================================================================
    
    async def verify_captcha(
        self,
        chat_id: int,
        user_id: int,
        answer: str
    ) -> bool:
        """Проверить ответ на captcha.
        
        Requirement 6.3: Grant full chat permissions on success
        """
        settings = await self.get_settings_async(chat_id)
        captcha_manager = CaptchaManager(self.bot, settings)
        
        is_correct = await captcha_manager.verify_answer(chat_id, user_id, answer)
        
        if is_correct:
            # Отправляем приветствие после успешного прохождения captcha
            if settings.welcome_enabled:
                try:
                    chat = await self.bot.get_chat(chat_id)
                    user = await self.bot.get_chat_member(chat_id, user_id)
                    
                    welcome_manager = WelcomeManager(self.bot)
                    await welcome_manager.send_welcome(
                        chat_id=chat_id,
                        user=user.user,
                        chat=chat,
                        settings=settings
                    )
                except TelegramError as exc:
                    log.warning(f"Не удалось отправить приветствие после captcha: {exc}")
        
        return is_correct
    
    # ========================================================================
    # LOGGING (Requirement 8)
    # ========================================================================
    
    async def get_mod_log(
        self,
        chat_id: int,
        limit: int = 20,
        user_id: Optional[int] = None
    ) -> List[ModAction]:
        """Получить лог действий модерации.
        
        Requirement 8.2: Display the last 20 moderation actions
        Requirement 8.3: Display all actions involving that user
        """
        from app.moderation.storage import load_mod_log_async
        return await load_mod_log_async(chat_id, limit, user_id)


# Глобальный экземпляр контроллера (создаётся при инициализации бота)
_controller: Optional[ModerationController] = None


def get_moderation_controller(bot: Bot) -> ModerationController:
    """Получить или создать глобальный экземпляр контроллера модерации.
    
    Args:
        bot: Telegram Bot instance
        
    Returns:
        ModerationController instance
    """
    global _controller
    if _controller is None:
        _controller = ModerationController(bot)
    return _controller


def init_moderation_controller(bot: Bot) -> ModerationController:
    """Инициализировать глобальный контроллер модерации.
    
    Вызывается при старте бота.
    
    Args:
        bot: Telegram Bot instance
        
    Returns:
        ModerationController instance
    """
    global _controller
    _controller = ModerationController(bot)
    log.info("ModerationController initialized")
    return _controller
