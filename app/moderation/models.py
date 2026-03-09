# Copyright (c) 2026 mogaqu
"""Модели данных для системы модерации."""
from dataclasses import dataclass, field
from typing import List, Optional
import time
import uuid


@dataclass
class ChatModSettings:
    """Настройки модерации для конкретного чата.
    
    Requirements: 7.2, 7.3, 7.4, 7.5, 7.6
    """
    chat_id: int
    
    # Welcome settings (Requirement 7.5)
    welcome_enabled: bool = False
    welcome_message: str = "Добро пожаловать, {username}!"
    welcome_delay_sec: int = 0
    welcome_auto_delete_sec: int = 0  # 0 = don't delete
    welcome_private: bool = False
    
    # Spam settings (Requirement 7.3)
    spam_enabled: bool = True
    spam_message_limit: int = 5
    spam_time_window_sec: int = 10
    spam_mute_duration_min: int = 5
    
    # Link filter for newbies (Requirement 7.6)
    link_filter_enabled: bool = True
    link_newbie_hours: int = 24
    link_action: str = "hold"  # delete, warn, hold
    link_whitelist: List[str] = field(default_factory=list)
    
    # Warn settings (Requirement 7.2)
    warn_mute_threshold: int = 3
    warn_ban_threshold: int = 5
    warn_mute_duration_hours: int = 24
    
    # Captcha settings (Requirement 7.4)
    captcha_enabled: bool = False
    captcha_timeout_sec: int = 120
    captcha_difficulty: str = "easy"  # easy, medium, hard
    captcha_fail_action: str = "kick"  # kick, mute
    
    # Content filter
    filter_words: List[str] = field(default_factory=list)
    filter_notify_user: bool = True
    
    # Logging
    log_channel_id: Optional[int] = None


    def validate(self) -> List[str]:
        """Валидация настроек. Возвращает список ошибок.
        
        Requirement 7.2: warn thresholds 1-10 for mute, 1-20 for ban
        Requirement 7.3: spam limit 1-20, time window 5-60, mute duration 1-1440
        Requirement 7.4: captcha timeout 30-600
        Requirement 7.5: welcome delay 0-30, auto-delete 0-3600
        Requirement 7.6: newbie period 0-168 hours
        """
        errors = []
        
        # Warn thresholds (Requirement 7.2)
        if not (1 <= self.warn_mute_threshold <= 10):
            errors.append(f"warn_mute_threshold должен быть от 1 до 10, получено: {self.warn_mute_threshold}")
        if not (1 <= self.warn_ban_threshold <= 20):
            errors.append(f"warn_ban_threshold должен быть от 1 до 20, получено: {self.warn_ban_threshold}")
        if self.warn_mute_threshold >= self.warn_ban_threshold:
            errors.append("warn_mute_threshold должен быть меньше warn_ban_threshold")
        
        # Spam settings (Requirement 7.3)
        if not (1 <= self.spam_message_limit <= 20):
            errors.append(f"spam_message_limit должен быть от 1 до 20, получено: {self.spam_message_limit}")
        if not (5 <= self.spam_time_window_sec <= 60):
            errors.append(f"spam_time_window_sec должен быть от 5 до 60, получено: {self.spam_time_window_sec}")
        if not (1 <= self.spam_mute_duration_min <= 1440):
            errors.append(f"spam_mute_duration_min должен быть от 1 до 1440, получено: {self.spam_mute_duration_min}")
        
        # Captcha settings (Requirement 7.4)
        if not (30 <= self.captcha_timeout_sec <= 600):
            errors.append(f"captcha_timeout_sec должен быть от 30 до 600, получено: {self.captcha_timeout_sec}")
        if self.captcha_difficulty not in ("easy", "medium", "hard"):
            errors.append(f"captcha_difficulty должен быть easy/medium/hard, получено: {self.captcha_difficulty}")
        if self.captcha_fail_action not in ("kick", "mute"):
            errors.append(f"captcha_fail_action должен быть kick/mute, получено: {self.captcha_fail_action}")
        
        # Welcome settings (Requirement 7.5)
        if not (0 <= self.welcome_delay_sec <= 30):
            errors.append(f"welcome_delay_sec должен быть от 0 до 30, получено: {self.welcome_delay_sec}")
        if not (0 <= self.welcome_auto_delete_sec <= 3600):
            errors.append(f"welcome_auto_delete_sec должен быть от 0 до 3600, получено: {self.welcome_auto_delete_sec}")
        
        # Link filter (Requirement 7.6)
        if not (0 <= self.link_newbie_hours <= 168):
            errors.append(f"link_newbie_hours должен быть от 0 до 168, получено: {self.link_newbie_hours}")
        if self.link_action not in ("delete", "warn", "hold"):
            errors.append(f"link_action должен быть delete/warn/hold, получено: {self.link_action}")
        
        return errors


@dataclass
class Warn:
    """Предупреждение пользователю.
    
    Requirement 3.1: record warning with reason, timestamp, and issuing admin
    """
    id: str
    chat_id: int
    user_id: int
    admin_id: int
    reason: str
    timestamp: float
    
    @classmethod
    def create(cls, chat_id: int, user_id: int, admin_id: int, reason: str) -> "Warn":
        """Создать новое предупреждение с автоматическим ID и timestamp."""
        return cls(
            id=str(uuid.uuid4()),
            chat_id=chat_id,
            user_id=user_id,
            admin_id=admin_id,
            reason=reason,
            timestamp=time.time()
        )


@dataclass
class ModAction:
    """Действие модерации для логирования.
    
    Requirement 8.1: record with timestamp, action type, target user, acting admin, and reason
    """
    id: str
    chat_id: int
    action_type: str  # warn, mute, unmute, ban, kick, delete, filter
    target_user_id: int
    admin_id: Optional[int]  # None for automatic actions
    reason: str
    timestamp: float
    auto: bool = False  # True if triggered automatically
    
    @classmethod
    def create(
        cls,
        chat_id: int,
        action_type: str,
        target_user_id: int,
        reason: str,
        admin_id: Optional[int] = None,
        auto: bool = False
    ) -> "ModAction":
        """Создать новое действие модерации с автоматическим ID и timestamp."""
        return cls(
            id=str(uuid.uuid4()),
            chat_id=chat_id,
            action_type=action_type,
            target_user_id=target_user_id,
            admin_id=admin_id,
            reason=reason,
            timestamp=time.time(),
            auto=auto
        )


@dataclass
class Captcha:
    """Captcha для проверки нового участника.
    
    Requirement 6.1: simple math or button captcha challenge
    """
    id: str
    chat_id: int
    user_id: int
    question: str
    answer: str
    expires_at: float
    message_id: Optional[int] = None  # ID сообщения с captcha для удаления
    
    @classmethod
    def create(
        cls,
        chat_id: int,
        user_id: int,
        question: str,
        answer: str,
        timeout_sec: int
    ) -> "Captcha":
        """Создать новую captcha с автоматическим ID и временем истечения."""
        return cls(
            id=str(uuid.uuid4()),
            chat_id=chat_id,
            user_id=user_id,
            question=question,
            answer=answer,
            expires_at=time.time() + timeout_sec
        )
    
    def is_expired(self) -> bool:
        """Проверить, истекла ли captcha."""
        return time.time() > self.expires_at
    
    def verify(self, user_answer: str) -> bool:
        """Проверить ответ пользователя."""
        return user_answer.strip().lower() == self.answer.strip().lower()
