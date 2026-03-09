# Copyright (c) 2026 mogaqu
"""Хранилище настроек модерации в Redis.

Ключи:
- mod_settings:{chat_id} - настройки модерации чата
- warns:{chat_id}:{user_id} - предупреждения пользователя
- modlog:{chat_id} - лог действий модерации

Requirement 7.7: sensible defaults with all features disabled until explicitly enabled

БЕЗОПАСНОСТЬ:
- Все ID валидируются как целые числа перед использованием в ключах
- Данные сериализуются через JSON (защита от injection)
"""
import asyncio
import json
from dataclasses import asdict
from typing import Dict, List, Optional, Any

from app.config import REDIS_URL
from app.logging_config import log
from app.security.data_protection import pseudonymize_id, pseudonymize_chat_id
from app.moderation.models import ChatModSettings, Warn, ModAction

import redis


def _validate_id(value: int, name: str = "ID") -> int:
    """Валидирует ID для предотвращения injection атак.
    
    Args:
        value: Значение для валидации
        name: Название параметра для сообщения об ошибке
        
    Returns:
        Валидированное целое число
        
    Raises:
        ValueError: Если значение не является валидным ID
    """
    if not isinstance(value, int):
        raise ValueError(f"{name} должен быть целым числом, получено: {type(value)}")
    # Telegram ID могут быть отрицательными (для групп/каналов)
    if abs(value) > 10**15:  # Разумный лимит для Telegram ID
        raise ValueError(f"{name} выходит за допустимые пределы: {value}")
    return value


def _sanitize_string(value: str, max_length: int = 1000) -> str:
    """Санитизирует строку для безопасного хранения.
    
    Args:
        value: Строка для санитизации
        max_length: Максимальная длина
        
    Returns:
        Безопасная строка
    """
    if not isinstance(value, str):
        return str(value)[:max_length]
    # Удаляем null bytes и ограничиваем длину
    return value.replace('\x00', '').strip()[:max_length]

# Используем тот же Redis клиент что и основное приложение
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# Префиксы ключей
MOD_SETTINGS_PREFIX = "mod_settings:"
WARNS_PREFIX = "warns:"
MODLOG_PREFIX = "modlog:"

# Максимальное количество записей в логе модерации
MAX_MODLOG_ENTRIES = 1000


def _get_default_settings(chat_id: int) -> ChatModSettings:
    """Получить настройки по умолчанию для нового чата.
    
    Requirement 7.7: all features disabled except spam filter
    """
    return ChatModSettings(
        chat_id=chat_id,
        # По умолчанию включен только спам-фильтр
        spam_enabled=True,
        # Остальные функции выключены
        welcome_enabled=False,
        captcha_enabled=False,
        link_filter_enabled=False,
    )


# ============================================================================
# SETTINGS OPERATIONS
# ============================================================================

def save_settings(settings: ChatModSettings) -> None:
    """Сохранить настройки модерации в Redis."""
    chat_id = _validate_id(settings.chat_id, "chat_id")
    key = f"{MOD_SETTINGS_PREFIX}{chat_id}"
    try:
        data = asdict(settings)
        redis_client.set(key, json.dumps(data, ensure_ascii=False))
    except Exception as exc:
        log.error(f"Не удалось сохранить настройки модерации: {exc}")
        raise


async def save_settings_async(settings: ChatModSettings) -> None:
    """Асинхронно сохранить настройки модерации."""
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, save_settings, settings)


def load_settings(chat_id: int) -> ChatModSettings:
    """Загрузить настройки модерации из Redis.
    
    Если настройки не найдены, возвращает настройки по умолчанию.
    """
    chat_id = _validate_id(chat_id, "chat_id")
    key = f"{MOD_SETTINGS_PREFIX}{chat_id}"
    try:
        raw_value = redis_client.get(key)
        if not raw_value:
            return _get_default_settings(chat_id)
        
        data = json.loads(raw_value)
        # Убедимся что chat_id соответствует
        data["chat_id"] = chat_id
        return ChatModSettings(**data)
    except json.JSONDecodeError as exc:
        log.warning(f"Некорректный JSON настроек для чата {pseudonymize_chat_id(chat_id)}: {exc}")
        return _get_default_settings(chat_id)
    except TypeError as exc:
        log.warning(f"Некорректные данные настроек для чата {pseudonymize_chat_id(chat_id)}: {exc}")
        return _get_default_settings(chat_id)
    except Exception as exc:
        log.error(f"Ошибка загрузки настроек для чата {pseudonymize_chat_id(chat_id)}: {exc}")
        return _get_default_settings(chat_id)


async def load_settings_async(chat_id: int) -> ChatModSettings:
    """Асинхронно загрузить настройки модерации."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, load_settings, chat_id)


def delete_settings(chat_id: int) -> bool:
    """Удалить настройки модерации чата."""
    key = f"{MOD_SETTINGS_PREFIX}{chat_id}"
    try:
        return redis_client.delete(key) > 0
    except Exception as exc:
        log.error(f"Не удалось удалить настройки для чата {pseudonymize_chat_id(chat_id)}: {exc}")
        return False


def export_settings(chat_id: int) -> Optional[str]:
    """Экспортировать настройки в JSON строку.
    
    Requirement 7.8: export settings as JSON
    """
    settings = load_settings(chat_id)
    data = asdict(settings)
    # Убираем chat_id из экспорта - он будет установлен при импорте
    del data["chat_id"]
    return json.dumps(data, ensure_ascii=False, indent=2)


def import_settings(chat_id: int, json_str: str) -> ChatModSettings:
    """Импортировать настройки из JSON строки.
    
    Requirement 7.8: import settings from JSON
    Raises ValueError if JSON is invalid or settings don't validate.
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Некорректный JSON: {exc}")
    
    # Устанавливаем chat_id
    data["chat_id"] = chat_id
    
    try:
        settings = ChatModSettings(**data)
    except TypeError as exc:
        raise ValueError(f"Некорректные поля настроек: {exc}")
    
    # Валидируем настройки
    errors = settings.validate()
    if errors:
        raise ValueError(f"Ошибки валидации: {'; '.join(errors)}")
    
    # Сохраняем
    save_settings(settings)
    return settings


# ============================================================================
# WARNS OPERATIONS
# ============================================================================

def _warns_key(chat_id: int, user_id: int) -> str:
    """Получить ключ для предупреждений пользователя."""
    chat_id = _validate_id(chat_id, "chat_id")
    user_id = _validate_id(user_id, "user_id")
    return f"{WARNS_PREFIX}{chat_id}:{user_id}"


def save_warn(warn: Warn) -> None:
    """Сохранить предупреждение в Redis (добавить в список)."""
    key = _warns_key(warn.chat_id, warn.user_id)
    try:
        data = asdict(warn)
        redis_client.rpush(key, json.dumps(data, ensure_ascii=False))
    except Exception as exc:
        log.error(f"Не удалось сохранить предупреждение: {exc}")
        raise


async def save_warn_async(warn: Warn) -> None:
    """Асинхронно сохранить предупреждение."""
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, save_warn, warn)


def load_warns(chat_id: int, user_id: int) -> List[Warn]:
    """Загрузить все предупреждения пользователя."""
    key = _warns_key(chat_id, user_id)
    try:
        raw_values = redis_client.lrange(key, 0, -1)
        warns = []
        for raw in raw_values:
            try:
                data = json.loads(raw)
                warns.append(Warn(**data))
            except (json.JSONDecodeError, TypeError) as exc:
                log.warning(f"Некорректные данные предупреждения: {exc}")
        return warns
    except Exception as exc:
        log.error(f"Ошибка загрузки предупреждений для {pseudonymize_chat_id(chat_id)}:{pseudonymize_id(user_id)}: {exc}")
        return []


async def load_warns_async(chat_id: int, user_id: int) -> List[Warn]:
    """Асинхронно загрузить предупреждения."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, load_warns, chat_id, user_id)


def count_warns(chat_id: int, user_id: int) -> int:
    """Получить количество предупреждений пользователя."""
    key = _warns_key(chat_id, user_id)
    try:
        return redis_client.llen(key)
    except Exception as exc:
        log.error(f"Ошибка подсчета предупреждений: {exc}")
        return 0


def clear_warns(chat_id: int, user_id: int) -> int:
    """Очистить все предупреждения пользователя. Возвращает количество удалённых."""
    key = _warns_key(chat_id, user_id)
    try:
        count = redis_client.llen(key)
        redis_client.delete(key)
        return count
    except Exception as exc:
        log.error(f"Ошибка очистки предупреждений: {exc}")
        return 0


async def clear_warns_async(chat_id: int, user_id: int) -> int:
    """Асинхронно очистить предупреждения."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, clear_warns, chat_id, user_id)


# ============================================================================
# MODLOG OPERATIONS
# ============================================================================

def _modlog_key(chat_id: int) -> str:
    """Получить ключ для лога модерации."""
    chat_id = _validate_id(chat_id, "chat_id")
    return f"{MODLOG_PREFIX}{chat_id}"


def save_mod_action(action: ModAction) -> None:
    """Сохранить действие модерации в лог."""
    key = _modlog_key(action.chat_id)
    try:
        data = asdict(action)
        with redis_client.pipeline() as pipe:
            pipe.lpush(key, json.dumps(data, ensure_ascii=False))
            # Ограничиваем размер лога
            pipe.ltrim(key, 0, MAX_MODLOG_ENTRIES - 1)
            pipe.execute()
    except Exception as exc:
        log.error(f"Не удалось сохранить действие модерации: {exc}")
        raise


async def save_mod_action_async(action: ModAction) -> None:
    """Асинхронно сохранить действие модерации."""
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, save_mod_action, action)


def load_mod_log(
    chat_id: int,
    limit: int = 20,
    user_id: Optional[int] = None
) -> List[ModAction]:
    """Загрузить лог модерации.
    
    Args:
        chat_id: ID чата
        limit: Максимальное количество записей
        user_id: Если указан, фильтровать по пользователю
    """
    key = _modlog_key(chat_id)
    try:
        # Загружаем больше записей если нужна фильтрация
        fetch_limit = limit * 5 if user_id else limit
        raw_values = redis_client.lrange(key, 0, fetch_limit - 1)
        
        actions = []
        for raw in raw_values:
            try:
                data = json.loads(raw)
                action = ModAction(**data)
                
                # Фильтрация по пользователю
                if user_id is not None and action.target_user_id != user_id:
                    continue
                    
                actions.append(action)
                
                if len(actions) >= limit:
                    break
            except (json.JSONDecodeError, TypeError) as exc:
                log.warning(f"Некорректные данные действия модерации: {exc}")
        
        return actions
    except Exception as exc:
        log.error(f"Ошибка загрузки лога модерации для чата {pseudonymize_chat_id(chat_id)}: {exc}")
        return []


async def load_mod_log_async(
    chat_id: int,
    limit: int = 20,
    user_id: Optional[int] = None
) -> List[ModAction]:
    """Асинхронно загрузить лог модерации."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, load_mod_log, chat_id, limit, user_id)
