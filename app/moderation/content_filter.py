# Copyright (c) 2026 mogaqu
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from telegram import Bot, User
from telegram.error import TelegramError

from app.logging_config import log
from app.moderation.models import ChatModSettings, ModAction
from app.moderation.storage import load_settings, save_settings, save_mod_action_async


@dataclass
class FilterCheckResult:
    """Результат проверки контента на запрещённые слова."""
    is_filtered: bool
    matched_word: Optional[str] = None
    
    @property
    def reason(self) -> str:
        """Причина фильтрации для логирования."""
        if self.matched_word:
            return f"filter:{self.matched_word}"
        return "filter"


class ContentFilter:
    """Фильтр контента для чата.
    
    Requirement 5.1: Automatically delete messages containing blacklisted words
    Case-insensitive matching with word boundaries support.
    """
    
    def __init__(self, settings: ChatModSettings):
        """
        Args:
            settings: Настройки модерации чата
        """
        self.settings = settings
        self.chat_id = settings.chat_id
        self._compiled_patterns: Optional[List[Tuple[str, re.Pattern]]] = None
    
    def _compile_patterns(self) -> List[Tuple[str, re.Pattern]]:
        """Компилировать регулярные выражения для слов из blacklist.
        
        Использует word boundaries для точного совпадения слов.
        """
        patterns = []
        for word in self.settings.filter_words:
            if not word:
                continue
            # Экранируем специальные символы regex
            escaped = re.escape(word)
            # Используем word boundaries для точного совпадения
            # \b работает для латиницы, для кириллицы используем (?<!\w) и (?!\w)
            pattern_str = rf"(?<![а-яёa-z0-9])({escaped})(?![а-яёa-z0-9])"
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                patterns.append((word, pattern))
            except re.error as exc:
                log.warning(f"Некорректный паттерн фильтра '{word}': {exc}")
        return patterns
    
    @property
    def patterns(self) -> List[Tuple[str, re.Pattern]]:
        """Получить скомпилированные паттерны (с кэшированием)."""
        if self._compiled_patterns is None:
            self._compiled_patterns = self._compile_patterns()
        return self._compiled_patterns
    
    def invalidate_cache(self) -> None:
        """Инвалидировать кэш паттернов после изменения списка слов."""
        self._compiled_patterns = None
    
    def check(self, text: str) -> FilterCheckResult:
        """Проверить текст на наличие запрещённых слов.
        
        Requirement 5.1: Case-insensitive matching with word boundaries
        
        Args:
            text: Текст для проверки
            
        Returns:
            FilterCheckResult с результатом проверки
        """
        if not text or not self.settings.filter_words:
            return FilterCheckResult(is_filtered=False)
        
        for word, pattern in self.patterns:
            if pattern.search(text):
                return FilterCheckResult(is_filtered=True, matched_word=word)
        
        return FilterCheckResult(is_filtered=False)
    
    def add_word(self, word: str) -> bool:
        """Добавить слово в blacklist.
        
        Requirement 5.1: Add word to blacklist via /addfilter
        
        Args:
            word: Слово для добавления
            
        Returns:
            True если слово добавлено, False если уже существует
        """
        word = word.strip().lower()
        if not word:
            return False
        
        # Ограничение длины слова для предотвращения DoS
        if len(word) > 100:
            return False
        
        # Ограничение количества слов в фильтре
        if len(self.settings.filter_words) >= 500:
            log.warning(f"Достигнут лимит слов в фильтре для чата {self.chat_id}")
            return False
        
        # Проверяем, нет ли уже такого слова (case-insensitive)
        existing_lower = [w.lower() for w in self.settings.filter_words]
        if word in existing_lower:
            return False
        
        self.settings.filter_words.append(word)
        self.invalidate_cache()
        save_settings(self.settings)
        return True
    
    def remove_word(self, word: str) -> bool:
        """Удалить слово из blacklist.
        
        Requirement 5.4: Remove word from blacklist via /removefilter
        
        Args:
            word: Слово для удаления
            
        Returns:
            True если слово удалено, False если не найдено
        """
        word = word.strip().lower()
        if not word:
            return False
        
        # Ищем слово case-insensitive
        for i, existing in enumerate(self.settings.filter_words):
            if existing.lower() == word:
                self.settings.filter_words.pop(i)
                self.invalidate_cache()
                save_settings(self.settings)
                return True
        
        return False
    
    def get_words(self) -> List[str]:
        """Получить список всех слов в blacklist.
        
        Requirement 5.3: Display all active filters
        
        Returns:
            Список слов в blacklist
        """
        return list(self.settings.filter_words)
    
    def clear_all(self) -> int:
        """Очистить весь blacklist.
        
        Returns:
            Количество удалённых слов
        """
        count = len(self.settings.filter_words)
        self.settings.filter_words = []
        self.invalidate_cache()
        save_settings(self.settings)
        return count


async def notify_user_violation(
    bot: Bot,
    user: User,
    matched_word: str,
    chat_title: str
) -> bool:
    """Отправить приватное уведомление пользователю о нарушении.
    
    Requirement 5.2: Notify user privately about the violation
    
    Args:
        bot: Telegram Bot instance
        user: Пользователь для уведомления
        matched_word: Слово, которое вызвало фильтрацию
        chat_title: Название чата
        
    Returns:
        True если уведомление отправлено, False если не удалось
    """
    try:
        await bot.send_message(
            chat_id=user.id,
            text=(
                f"⚠️ Ваше сообщение в чате «{chat_title}» было удалено.\n\n"
                f"Причина: сообщение содержит запрещённое слово.\n\n"
                f"Пожалуйста, соблюдайте правила чата."
            )
        )
        return True
    except TelegramError as exc:
        # Пользователь мог заблокировать бота или не начинал с ним диалог
        log.debug(f"Не удалось отправить уведомление пользователю {user.id}: {exc}")
        return False


async def check_and_filter_message(
    settings: ChatModSettings,
    text: str,
    user: User,
    message_id: int,
    bot: Bot,
    chat_title: str
) -> FilterCheckResult:
    """Проверить сообщение и выполнить действия при нарушении.
    
    Args:
        settings: Настройки модерации чата
        text: Текст сообщения
        user: Автор сообщения
        message_id: ID сообщения
        bot: Telegram Bot instance
        chat_title: Название чата
        
    Returns:
        FilterCheckResult с результатом проверки
    """
    content_filter = ContentFilter(settings)
    result = content_filter.check(text)
    
    if result.is_filtered:
        # Логируем действие
        action = ModAction.create(
            chat_id=settings.chat_id,
            action_type="filter",
            target_user_id=user.id,
            reason=result.reason,
            auto=True
        )
        await save_mod_action_async(action)
        
        # Отправляем приватное уведомление если включено
        if settings.filter_notify_user:
            await notify_user_violation(
                bot=bot,
                user=user,
                matched_word=result.matched_word or "",
                chat_title=chat_title
            )
    
    return result


# ============================================================================
# SYNC HELPER FUNCTIONS
# ============================================================================

def add_filter_word(chat_id: int, word: str) -> bool:
    """Добавить слово в фильтр чата (синхронно).
    
    Args:
        chat_id: ID чата
        word: Слово для добавления
        
    Returns:
        True если добавлено, False если уже существует
    """
    settings = load_settings(chat_id)
    content_filter = ContentFilter(settings)
    return content_filter.add_word(word)


def remove_filter_word(chat_id: int, word: str) -> bool:
    """Удалить слово из фильтра чата (синхронно).
    
    Args:
        chat_id: ID чата
        word: Слово для удаления
        
    Returns:
        True если удалено, False если не найдено
    """
    settings = load_settings(chat_id)
    content_filter = ContentFilter(settings)
    return content_filter.remove_word(word)


def get_filter_words(chat_id: int) -> List[str]:
    """Получить список слов в фильтре чата (синхронно).
    
    Args:
        chat_id: ID чата
        
    Returns:
        Список слов в blacklist
    """
    settings = load_settings(chat_id)
    return list(settings.filter_words)


def check_content(chat_id: int, text: str) -> FilterCheckResult:
    """Проверить текст на запрещённые слова (синхронно).
    
    Args:
        chat_id: ID чата
        text: Текст для проверки
        
    Returns:
        FilterCheckResult с результатом
    """
    settings = load_settings(chat_id)
    content_filter = ContentFilter(settings)
    return content_filter.check(text)
