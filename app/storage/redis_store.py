# Copyright (c) 2026 mogaqu
import asyncio
import base64
import json
import re
import secrets
import time
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Sequence

import redis
from telegram import User

from app.config import (
    CONFIG_KEY_PREFIX,
    GAME_CODE_PREFIX,
    GAME_LIST_KEY,
    GAME_TTL_SECONDS,
    GAMES_BY_AUTHOR_PREFIX,
    HISTORY_KEY_PREFIX,
    LOGIN_CODE_PREFIX,
    LOGIN_CODE_TTL_SECONDS,
    REDIS_URL,
    USER_KEY_PREFIX,
)
from app.logging_config import log
from app.state import ChatConfig, configs, history, user_profiles

redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
try:
    redis_client.ping()
except Exception as exc:
    raise RuntimeError("Не удалось подключиться к Redis") from exc


def convert_part_to_dict(part: Any):
    if hasattr(part, "inline_data") and getattr(part.inline_data, "data", None) is not None and getattr(
        part.inline_data, "mime_type", None
    ):
        encoded_data = base64.b64encode(part.inline_data.data).decode("utf-8")
        return {"inline_data": {"mime_type": part.inline_data.mime_type, "data": encoded_data}}
    if hasattr(part, "text"):
        return {"text": part.text}
    if isinstance(part, dict):
        inline_data = part.get("inline_data")
        if isinstance(inline_data, dict) and inline_data.get("mime_type") and inline_data.get("data") is not None:
            data_field = inline_data["data"]
            if isinstance(data_field, str):
                encoded_data = data_field
            else:
                encoded_data = base64.b64encode(bytes(data_field)).decode("utf-8")
            return {"inline_data": {"mime_type": inline_data.get("mime_type"), "data": encoded_data}}
        if part.get("mime_type") and part.get("data") is not None:
            data_field = part["data"]
            if isinstance(data_field, str):
                encoded_data = data_field
            else:
                encoded_data = base64.b64encode(bytes(data_field)).decode("utf-8")
            return {"inline_data": {"mime_type": part.get("mime_type"), "data": encoded_data}}
        return part
    if isinstance(part, (bytes, bytearray, memoryview)):
        encoded_data = base64.b64encode(bytes(part)).decode("utf-8")
        return {"inline_data": {"mime_type": "application/octet-stream", "data": encoded_data}}
    return str(part)


def convert_history_to_dict(history_item: Any):
    if hasattr(history_item, "role") and hasattr(history_item, "parts"):
        return {
            "role": history_item.role,
            "parts": [convert_part_to_dict(part) for part in history_item.parts],
        }
    if isinstance(history_item, dict):
        if "parts" in history_item:
            return {
                "role": history_item.get("role"),
                "parts": [convert_part_to_dict(part) for part in history_item["parts"]],
            }
        return history_item
    return history_item


def _deserialize_part(part: Any):
    if isinstance(part, dict):
        if "text" in part:
            return {"text": part["text"]}
        inline_data = part.get("inline_data")
        if isinstance(inline_data, dict) and inline_data.get("mime_type") and inline_data.get("data"):
            try:
                return {
                    "inline_data": {
                        "mime_type": inline_data["mime_type"],
                        "data": base64.b64decode(inline_data["data"].encode("utf-8")),
                    }
                }
            except Exception as exc:
                log.warning(f"Не удалось десериализовать часть истории: {exc}")
                return {"inline_data": inline_data}
        if part.get("mime_type") and part.get("data"):
            try:
                return {
                    "inline_data": {
                        "mime_type": part["mime_type"],
                        "data": base64.b64decode(part["data"].encode("utf-8")),
                    }
                }
            except Exception as exc:
                log.warning(f"Не удалось десериализовать часть истории (плоская запись): {exc}")
                return {"inline_data": part}
    return part


def _sanitize_redis_key(key: str) -> str:
    """Санидирует ключ Redis для предотвращения инъекций"""
    sanitized = re.sub(r'[{}\[\]\':"\\|<>?]', '', str(key))
    if len(sanitized) > 250:
        sanitized = sanitized[:250]
    return sanitized

def load_data():
    log.info("Загрузка данных из Redis...")
    
    # Импортируем для расшифровки
    from app.security.data_protection import decrypt_history
    
    try:
        loaded_history: Dict[int, List[Dict[str, Any]]] = {}
        for key in redis_client.scan_iter(match=_sanitize_redis_key(f"{HISTORY_KEY_PREFIX}*")):
            key_str = key.decode('utf-8') if isinstance(key, bytes) else key
            parts = key_str.split(":", 1)
            if len(parts) < 2:
                log.warning(f"Пропускаем некорректный ключ истории: {key_str}")
                continue
            chat_id_part = parts[1]
            raw_value = redis_client.get(key)
            if not raw_value:
                continue
            
            # Расшифровываем историю если зашифрована
            decrypted_value = decrypt_history(raw_value)
            if decrypted_value is None:
                log.warning(f"Не удалось расшифровать историю для чата {chat_id_part}")
                continue
            
            try:
                chat_history = json.loads(decrypted_value)
            except json.JSONDecodeError as exc:
                log.warning(f"Некорректный JSON истории для чата {chat_id_part}: {exc}")
                continue
            try:
                chat_id = int(chat_id_part)
            except ValueError:
                log.warning(f"Пропускаем историю с некорректным chat_id: {chat_id_part}")
                continue
            loaded_history[chat_id] = [
                {
                    "role": item.get("role"),
                    "parts": [_deserialize_part(part) for part in item.get("parts", [])],
                }
                for item in chat_history
            ]
        history.clear()
        history.update(loaded_history)
        log.info(f"Загружено {len(history)} историй чатов из Redis.")
    except Exception as exc:
        log.error(f"Ошибка при загрузке историй из Redis: {exc}", exc_info=True)
        history.clear()

    try:
        loaded_configs: Dict[int, ChatConfig] = {}
        for key in redis_client.scan_iter(match=_sanitize_redis_key(f"{CONFIG_KEY_PREFIX}*")):
            key_str = key.decode('utf-8') if isinstance(key, bytes) else key
            parts = key_str.split(":", 1)
            if len(parts) < 2:
                log.warning(f"Пропускаем некорректный ключ конфигурации: {key_str}")
                continue
            chat_id_part = parts[1]
            raw_value = redis_client.get(key)
            if not raw_value:
                continue
            try:
                config_payload = json.loads(raw_value)
            except json.JSONDecodeError as exc:
                log.warning(f"Некорректный JSON конфигурации для чата {chat_id_part}: {exc}")
                continue
            try:
                chat_id = int(chat_id_part)
            except ValueError:
                log.warning(f"Пропускаем конфигурацию с некорректным chat_id: {chat_id_part}")
                continue
            try:
                loaded_configs[chat_id] = ChatConfig(**config_payload)
            except TypeError as exc:
                log.warning(f"Некорректные данные конфигурации для чата {chat_id}: {exc}")
        configs.clear()
        configs.update(loaded_configs)
        log.info(f"Загружено {len(configs)} конфигураций чатов из Redis.")
    except Exception as exc:
        log.error(f"Ошибка при загрузке конфигураций из Redis: {exc}", exc_info=True)
        configs.clear()

    # Импортируем здесь чтобы избежать циклических импортов
    from app.security.data_protection import decrypt_pii
    
    try:
        loaded_users: Dict[int, Dict[int, Dict[str, Any]]] = {}
        for key in redis_client.scan_iter(match=_sanitize_redis_key(f"{USER_KEY_PREFIX}*")):
            key_str = key.decode('utf-8') if isinstance(key, bytes) else key
            parts = key_str.split(":", 1)
            if len(parts) < 2:
                log.warning(f"Пропускаем некорректный ключ профиля: {key_str}")
                continue
            chat_id_part = parts[1]
            raw_value = redis_client.get(key)
            if not raw_value:
                continue
            try:
                users_payload = json.loads(raw_value)
            except json.JSONDecodeError as exc:
                log.warning(f"Некорректный JSON профилей пользователей для чата {chat_id_part}: {exc}")
                continue
            try:
                chat_id = int(chat_id_part)
            except ValueError:
                log.warning(f"Пропускаем профили с некорректным chat_id: {chat_id_part}")
                continue
            try:
                loaded_users[chat_id] = {
                    int(user_id): decrypt_pii(profile)  # Расшифровываем PII при загрузке
                    for user_id, profile in users_payload.items()
                    if isinstance(profile, dict)
                }
            except Exception as exc:
                log.warning(f"Некорректные данные профилей для чата {chat_id}: {exc}")
        user_profiles.clear()
        user_profiles.update(loaded_users)
        log.info(f"Загружено профилей пользователей для {len(user_profiles)} чатов из Redis.")
    except Exception as exc:
        log.error(f"Ошибка при загрузке профилей пользователей из Redis: {exc}", exc_info=True)
        user_profiles.clear()


def save_chat_data(chat_id: int):
    """Сохраняет данные чата в Redis с защитой персональных данных.
    
    БЕЗОПАСНОСТЬ:
    - История диалогов шифруется
    - Профили пользователей шифруются перед сохранением
    - Конфиги не содержат PII
    """
    # Импортируем здесь чтобы избежать циклических импортов
    from app.security.data_protection import encrypt_pii, encrypt_history
    
    history_key = _sanitize_redis_key(f"{HISTORY_KEY_PREFIX}{chat_id}")
    config_key = _sanitize_redis_key(f"{CONFIG_KEY_PREFIX}{chat_id}")

    try:
        with redis_client.pipeline() as pipe:
            if chat_id in history:
                serialized_history = [convert_history_to_dict(item) for item in history[chat_id]]
                history_json = json.dumps(serialized_history, ensure_ascii=False)
                # Шифруем историю диалогов!
                encrypted_history = encrypt_history(history_json)
                pipe.set(history_key, encrypted_history)
                log.info(f"Saved history for chat {chat_id}")
            else:
                pipe.delete(history_key)

            if chat_id in configs:
                pipe.set(config_key, json.dumps(asdict(configs[chat_id]), ensure_ascii=False))
                log.info(f"Saved config for chat {chat_id}: {asdict(configs[chat_id])}")
            else:
                pipe.delete(config_key)

            users_key = _sanitize_redis_key(f"{USER_KEY_PREFIX}{chat_id}")
            if chat_id in user_profiles and user_profiles[chat_id]:
                # Шифруем персональные данные перед сохранением
                serialized_users = {}
                for uid, profile in user_profiles[chat_id].items():
                    # Шифруем PII в профиле
                    protected_profile = encrypt_pii(profile.copy())
                    # Используем псевдоним как ключ (опционально, для дополнительной защиты)
                    serialized_users[str(uid)] = protected_profile
                pipe.set(users_key, json.dumps(serialized_users, ensure_ascii=False))
            else:
                pipe.delete(users_key)

            pipe.execute()
    except Exception as exc:
        log.error(f"Не удалось сохранить данные чата в Redis: {exc}", exc_info=True)


async def persist_chat_data(chat_id: int):
    log.info(f"Persisting data for chat {chat_id}")
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, save_chat_data, chat_id)
    log.info(f"Data persisted for chat {chat_id}")


def record_user_profile(chat_id: int, user: Optional[User]) -> bool:
    """Записывает профиль пользователя с защитой персональных данных.
    
    БЕЗОПАСНОСТЬ:
    - Персональные данные (username, имена) шифруются перед сохранением
    - В памяти хранятся расшифрованные данные для работы бота
    - В Redis сохраняются зашифрованные данные
    """
    if not user:
        return False
    
    # Импортируем здесь чтобы избежать циклических импортов
    from app.security.data_protection import encrypt_pii
    
    profile: Dict[str, Any] = {
        "id": user.id,
        "username": user.username or None,
        "first_name": user.first_name or None,
        "last_name": user.last_name or None,
        "full_name": getattr(user, "full_name", None)
        or " ".join(filter(None, [user.first_name, user.last_name]))
        or None,
        "language_code": user.language_code or None,
        "is_bot": user.is_bot,
        "updated_at": time.time(),
    }
    cleaned_profile = {key: value for key, value in profile.items() if value is not None}
    chat_profiles = user_profiles.setdefault(chat_id, {})
    existing = chat_profiles.get(user.id)
    if existing != cleaned_profile:
        chat_profiles[user.id] = cleaned_profile
        return True
    return False


def is_duplicate_update(update_id: int) -> bool:
    """Проверяет, обрабатывался ли уже этот update_id."""
    key = f"processed_update:{update_id}"
    if redis_client.exists(key):
        return True
    # Храним только последний час обработанных update_id
    redis_client.setex(key, 3600, "1")
    return False


def _cleanup_game_indexes(pipeline, cutoff_timestamp: float, author_key: Optional[str]) -> None:
    pipeline.zremrangebyscore(GAME_LIST_KEY, "-inf", cutoff_timestamp)
    pipeline.expire(GAME_LIST_KEY, GAME_TTL_SECONDS)
    if author_key:
        pipeline.zremrangebyscore(author_key, "-inf", cutoff_timestamp)
        pipeline.expire(author_key, GAME_TTL_SECONDS)


def store_game_payload(game_id: str, payload: Dict[str, Any]) -> None:
    key = f"{GAME_CODE_PREFIX}{game_id}"
    timestamp = payload.get("created_at") or time.time()
    author_id = payload.get("author_id")
    author_key = f"{GAMES_BY_AUTHOR_PREFIX}{author_id}" if author_id else None
    cutoff = timestamp - GAME_TTL_SECONDS
    try:
        serialized = json.dumps(payload, ensure_ascii=False)
        with redis_client.pipeline() as pipe:
            pipe.set(key, serialized, ex=GAME_TTL_SECONDS)
            pipe.zadd(GAME_LIST_KEY, {game_id: timestamp})
            if author_key:
                pipe.zadd(author_key, {game_id: timestamp})
            _cleanup_game_indexes(pipe, cutoff, author_key)
            pipe.execute()
    except Exception as exc:
        log.error(f"Не удалось сохранить игру {game_id} в Redis: {exc}", exc_info=True)
        raise


def load_game_payload(game_id: str) -> Optional[Dict[str, Any]]:
    key = f"{GAME_CODE_PREFIX}{game_id}"
    try:
        raw_value = redis_client.get(key)
    except Exception as exc:
        log.error(f"Не удалось загрузить игру {game_id} из Redis: {exc}", exc_info=True)
        raise

    if not raw_value:
        return None

    try:
        decoded: Dict[str, Any] = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        log.warning(f"Некорректный JSON игры {game_id}: {exc}")
        return None
    return decoded


def _fetch_game_payloads(game_ids: Sequence[str]) -> List[Dict[str, Any]]:
    if not game_ids:
        return []
    keys = [f"{GAME_CODE_PREFIX}{gid}" for gid in game_ids]
    try:
        raw_values = redis_client.mget(keys)
    except Exception as exc:
        log.error("Не удалось выполнить mget для игр: %s", exc, exc_info=True)
        return []
    results: List[Dict[str, Any]] = []
    for gid, raw_value in zip(game_ids, raw_values):
        if not raw_value:
            continue
        try:
            decoded = json.loads(raw_value)
        except json.JSONDecodeError:
            log.warning("Некорректный JSON при загрузке игры %s из mget", gid)
            continue
        decoded.setdefault("id", gid)
        results.append(decoded)
    return results


def list_recent_games(limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
    try:
        game_ids = redis_client.zrevrange(GAME_LIST_KEY, offset, offset + limit - 1)
    except Exception as exc:
        log.error("Не удалось получить список игр: %s", exc, exc_info=True)
        return []
    return _fetch_game_payloads(game_ids)


def list_games_for_author(author_id: int, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
    key = f"{GAMES_BY_AUTHOR_PREFIX}{author_id}"
    try:
        game_ids = redis_client.zrevrange(key, offset, offset + limit - 1)
    except Exception as exc:
        log.error("Не удалось получить игры пользователя %s: %s", author_id, exc, exc_info=True)
        return []
    return _fetch_game_payloads(game_ids)


CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _generate_code(length: int = 6) -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(length))


def create_login_code(
    user_id: int,
    chat_id: Optional[int],
    username: Optional[str] = None,
    display_name: Optional[str] = None,
    length: int = 6,
) -> str:
    attempts = 0
    while attempts < 5:
        code = _generate_code(length)
        key = f"{LOGIN_CODE_PREFIX}{code}"
        payload = {
            "user_id": user_id,
            "chat_id": chat_id,
            "username": username,
            "display_name": display_name,
            "issued_at": time.time(),
        }
        try:
            if redis_client.setnx(key, json.dumps(payload, ensure_ascii=False)):
                redis_client.expire(key, LOGIN_CODE_TTL_SECONDS)
                return code
        except Exception as exc:
            log.error("Не удалось сохранить код входа: %s", exc, exc_info=True)
            raise
        attempts += 1
    raise RuntimeError("Не удалось сгенерировать уникальный код входа.")


def consume_login_code(code: str) -> Optional[Dict[str, Any]]:
    # Валидация кода для предотвращения инъекций
    sanitized_code = code.strip().upper()
    # Ограничение длины для предотвращения DoS
    if len(sanitized_code) > 20:
        log.warning("Попытка использовать слишком длинный код входа")
        return None
    if not re.match(r'^[A-Z0-9]{6,}$', sanitized_code):
        log.warning("Попытка использовать некорректный код входа: %s", code[:10])
        return None
    
    key = f"{LOGIN_CODE_PREFIX}{sanitized_code}"
    try:
        with redis_client.pipeline() as pipe:
            pipe.get(key)
            pipe.delete(key)
            result, _ = pipe.execute()
    except Exception as exc:
        log.error("Не удалось прочитать код входа %s: %s", sanitized_code, exc, exc_info=True)
        return None
    if not result:
        return None
    try:
        decoded: Dict[str, Any] = json.loads(result)
    except json.JSONDecodeError:
        log.warning("Некорректный JSON в коде входа %s", sanitized_code)
        return None
    return decoded
