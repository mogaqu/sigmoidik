# Copyright (c) 2026 mogaqu
"""Модуль модерации для Chat Admin Bot.

Компоненты:
- ModerationController: Центральная точка входа для всех операций модерации
- SpamFilter: Антиспам система
- WarnSystem: Система предупреждений
- ContentFilter: Фильтрация контента
- CaptchaManager: Captcha для новых участников
- WelcomeManager: Приветствия новых участников
- ModLogger: Логирование действий модерации
"""

from app.moderation.controller import (
    ModerationController,
    ModerationAction,
    ModerationResult,
    get_moderation_controller,
    init_moderation_controller,
)
from app.moderation.models import ChatModSettings, Warn, ModAction, Captcha
from app.moderation.spam import SpamFilter, SpamAction, SpamCheckResult
from app.moderation.warns import WarnSystem, WarnResult, WarnEscalation
from app.moderation.content_filter import ContentFilter, FilterCheckResult
from app.moderation.captcha import CaptchaManager, CaptchaProvider
from app.moderation.welcome import WelcomeManager
from app.moderation.logger import ModLogger

__all__ = [
    # Controller
    "ModerationController",
    "ModerationAction",
    "ModerationResult",
    "get_moderation_controller",
    "init_moderation_controller",
    # Models
    "ChatModSettings",
    "Warn",
    "ModAction",
    "Captcha",
    # Spam
    "SpamFilter",
    "SpamAction",
    "SpamCheckResult",
    # Warns
    "WarnSystem",
    "WarnResult",
    "WarnEscalation",
    # Content Filter
    "ContentFilter",
    "FilterCheckResult",
    # Captcha
    "CaptchaManager",
    "CaptchaProvider",
    # Welcome
    "WelcomeManager",
    # Logger
    "ModLogger",
]
