# Copyright (c) 2026 mogaqu
"""Система предупреждений (warns) для модерации чатов.

Requirements:
- 3.1: Record warning with reason, timestamp, and issuing admin
- 3.2: Auto-mute user after N warnings
- 3.3: Auto-ban user after M warnings
- 3.4: Display all warnings for a user
- 3.5: Clear all warnings for a user
"""
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from app.logging_config import log
from app.security.data_protection import pseudonymize_id, pseudonymize_chat_id
from app.moderation.models import ChatModSettings, Warn, ModAction
from app.moderation.storage import (
    load_settings,
    load_warns,
    save_warn,
    clear_warns as storage_clear_warns,
    count_warns,
    save_mod_action,
    load_warns_async,
    save_warn_async,
    clear_warns_async,
    save_mod_action_async,
    load_settings_async,
)


class WarnEscalation(Enum):
    """Результат эскалации после добавления предупреждения."""
    NONE = "none"
    MUTE = "mute"
    BAN = "ban"


@dataclass
class WarnResult:
    """Результат добавления предупреждения.
    
    Attributes:
        warn: Созданное предупреждение
        total_warns: Общее количество предупреждений после добавления
        escalation: Тип эскалации (none/mute/ban)
        mute_duration_hours: Длительность мута в часах (если escalation == MUTE)
    """
    warn: Warn
    total_warns: int
    escalation: WarnEscalation
    mute_duration_hours: int = 0


class WarnSystem:
    """Система предупреждений с автоэскалацией.
    
    Requirements:
    - 3.1: Record warning with reason, timestamp, and issuing admin
    - 3.2: Auto-mute user after warn_mute_threshold warnings
    - 3.3: Auto-ban user after warn_ban_threshold warnings
    - 3.4: Display all warnings for a user
    - 3.5: Clear all warnings for a user
    """
    
    def __init__(self, settings: Optional[ChatModSettings] = None):
        """Инициализация системы предупреждений.
        
        Args:
            settings: Настройки модерации чата. Если None, будут загружены при вызове методов.
        """
        self._settings = settings

    def _get_settings(self, chat_id: int) -> ChatModSettings:
        """Получить настройки для чата."""
        if self._settings and self._settings.chat_id == chat_id:
            return self._settings
        return load_settings(chat_id)
    
    async def _get_settings_async(self, chat_id: int) -> ChatModSettings:
        """Асинхронно получить настройки для чата."""
        if self._settings and self._settings.chat_id == chat_id:
            return self._settings
        return await load_settings_async(chat_id)
    
    def _determine_escalation(
        self, 
        warn_count: int, 
        settings: ChatModSettings
    ) -> tuple[WarnEscalation, int]:
        """Определить тип эскалации на основе количества предупреждений.
        
        Requirement 3.2: Auto-mute after warn_mute_threshold
        Requirement 3.3: Auto-ban after warn_ban_threshold
        
        Args:
            warn_count: Текущее количество предупреждений
            settings: Настройки модерации
            
        Returns:
            Tuple (тип эскалации, длительность мута в часах)
        """
        # Бан имеет приоритет над мутом
        if warn_count >= settings.warn_ban_threshold:
            return WarnEscalation.BAN, 0
        
        if warn_count >= settings.warn_mute_threshold:
            return WarnEscalation.MUTE, settings.warn_mute_duration_hours
        
        return WarnEscalation.NONE, 0
    
    def add_warn(
        self,
        chat_id: int,
        user_id: int,
        admin_id: int,
        reason: str
    ) -> WarnResult:
        """Добавить предупреждение пользователю.
        
        Requirement 3.1: Record warning with reason, timestamp, and issuing admin
        
        Args:
            chat_id: ID чата
            user_id: ID пользователя
            admin_id: ID админа, выдавшего предупреждение
            reason: Причина предупреждения
            
        Returns:
            WarnResult с информацией о предупреждении и эскалации
        """
        # Создаём предупреждение
        warn = Warn.create(
            chat_id=chat_id,
            user_id=user_id,
            admin_id=admin_id,
            reason=reason
        )
        
        # Сохраняем в Redis
        save_warn(warn)
        
        # Получаем общее количество предупреждений
        total_warns = count_warns(chat_id, user_id)
        
        # Определяем эскалацию
        settings = self._get_settings(chat_id)
        escalation, mute_hours = self._determine_escalation(total_warns, settings)
        
        log.info(
            f"Warn added: chat={chat_id}, user={user_id}, admin={admin_id}, "
            f"total={total_warns}, escalation={escalation.value}"
        )
        
        return WarnResult(
            warn=warn,
            total_warns=total_warns,
            escalation=escalation,
            mute_duration_hours=mute_hours
        )
    
    async def add_warn_async(
        self,
        chat_id: int,
        user_id: int,
        admin_id: int,
        reason: str
    ) -> WarnResult:
        """Асинхронно добавить предупреждение пользователю.
        
        Args:
            chat_id: ID чата
            user_id: ID пользователя
            admin_id: ID админа, выдавшего предупреждение
            reason: Причина предупреждения
            
        Returns:
            WarnResult с информацией о предупреждении и эскалации
        """
        import asyncio
        
        # Создаём предупреждение
        warn = Warn.create(
            chat_id=chat_id,
            user_id=user_id,
            admin_id=admin_id,
            reason=reason
        )
        
        # Сохраняем в Redis
        await save_warn_async(warn)
        
        # Получаем общее количество предупреждений (синхронно, т.к. count_warns быстрый)
        loop = asyncio.get_running_loop()
        total_warns = await loop.run_in_executor(None, count_warns, chat_id, user_id)
        
        # Определяем эскалацию
        settings = await self._get_settings_async(chat_id)
        escalation, mute_hours = self._determine_escalation(total_warns, settings)
        
        log.info(
            f"Warn added: chat={chat_id}, user={user_id}, admin={admin_id}, "
            f"total={total_warns}, escalation={escalation.value}"
        )
        
        return WarnResult(
            warn=warn,
            total_warns=total_warns,
            escalation=escalation,
            mute_duration_hours=mute_hours
        )
    
    def get_warns(self, chat_id: int, user_id: int) -> List[Warn]:
        """Получить все предупреждения пользователя.
        
        Requirement 3.4: Display all warnings for that user with dates and reasons
        
        Args:
            chat_id: ID чата
            user_id: ID пользователя
            
        Returns:
            Список предупреждений, отсортированный по времени (новые первые)
        """
        warns = load_warns(chat_id, user_id)
        # Сортируем по времени (новые первые)
        warns.sort(key=lambda w: w.timestamp, reverse=True)
        return warns
    
    async def get_warns_async(self, chat_id: int, user_id: int) -> List[Warn]:
        """Асинхронно получить все предупреждения пользователя.
        
        Args:
            chat_id: ID чата
            user_id: ID пользователя
            
        Returns:
            Список предупреждений, отсортированный по времени (новые первые)
        """
        warns = await load_warns_async(chat_id, user_id)
        warns.sort(key=lambda w: w.timestamp, reverse=True)
        return warns
    
    def clear_warns(self, chat_id: int, user_id: int) -> int:
        """Очистить все предупреждения пользователя.
        
        Requirement 3.5: Remove all warnings for that user
        
        Args:
            chat_id: ID чата
            user_id: ID пользователя
            
        Returns:
            Количество удалённых предупреждений
        """
        count = storage_clear_warns(chat_id, user_id)
        log.info(f"Cleared {count} warns for user {pseudonymize_id(user_id)} in chat {pseudonymize_chat_id(chat_id)}")
        return count
    
    async def clear_warns_async(self, chat_id: int, user_id: int) -> int:
        """Асинхронно очистить все предупреждения пользователя.
        
        Args:
            chat_id: ID чата
            user_id: ID пользователя
            
        Returns:
            Количество удалённых предупреждений
        """
        count = await clear_warns_async(chat_id, user_id)
        log.info(f"Cleared {count} warns for user {pseudonymize_id(user_id)} in chat {pseudonymize_chat_id(chat_id)}")
        return count
    
    def get_warn_count(self, chat_id: int, user_id: int) -> int:
        """Получить количество предупреждений пользователя.
        
        Args:
            chat_id: ID чата
            user_id: ID пользователя
            
        Returns:
            Количество предупреждений
        """
        return count_warns(chat_id, user_id)


# Вспомогательные функции для форматирования

def format_warn_message(warn: Warn, include_admin: bool = True) -> str:
    """Форматировать предупреждение для отображения.
    
    Args:
        warn: Предупреждение
        include_admin: Включать ли информацию об админе
        
    Returns:
        Отформатированная строка
    """
    from datetime import datetime
    
    dt = datetime.fromtimestamp(warn.timestamp)
    date_str = dt.strftime("%d.%m.%Y %H:%M")
    
    parts = [f"📅 {date_str}"]
    if warn.reason:
        parts.append(f"📝 {warn.reason}")
    if include_admin:
        parts.append(f"👮 Admin ID: {warn.admin_id}")
    
    return " | ".join(parts)


def format_warns_list(warns: List[Warn], user_mention: str) -> str:
    """Форматировать список предупреждений для отображения.
    
    Args:
        warns: Список предупреждений
        user_mention: Упоминание пользователя (@username или имя)
        
    Returns:
        Отформатированная строка со списком предупреждений
    """
    if not warns:
        return f"✅ У {user_mention} нет предупреждений."
    
    lines = [f"⚠️ Предупреждения {user_mention} ({len(warns)}):"]
    for i, warn in enumerate(warns, 1):
        lines.append(f"\n{i}. {format_warn_message(warn)}")
    
    return "\n".join(lines)
