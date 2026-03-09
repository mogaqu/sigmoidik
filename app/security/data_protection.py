# Copyright (c) 2025 sprowii
"""Защита персональных данных.

Модуль обеспечивает:
- Псевдонимизацию user_id (хэширование с солью)
- Шифрование чувствительных данных
- Безопасное удаление данных
- Соответствие GDPR/ФЗ-152

При взломе БД злоумышленник получит только:
- Хэшированные ID (нельзя восстановить реальные)
- Зашифрованные данные (без ключа бесполезны)
"""
import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Any, Dict, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.logging_config import log


# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

# Соль для хэширования ID - должна быть в переменных окружения!
# Если не задана, генерируется при запуске (данные станут недоступны после рестарта)
_HASH_SALT = os.getenv("DATA_HASH_SALT")
if not _HASH_SALT:
    log.warning(
        "DATA_HASH_SALT не задан! Генерирую временную соль. "
        "ВАЖНО: Задайте DATA_HASH_SALT в переменных окружения для production!"
    )
    _HASH_SALT = secrets.token_hex(32)

# Ключ шифрования для чувствительных данных
_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY")
_fernet: Optional[Fernet] = None

if _ENCRYPTION_KEY:
    try:
        # Если ключ в base64 формате Fernet
        _fernet = Fernet(_ENCRYPTION_KEY.encode())
    except Exception:
        # Если обычный пароль - деривируем ключ
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=_HASH_SALT.encode()[:16],
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(_ENCRYPTION_KEY.encode()))
        _fernet = Fernet(key)
else:
    log.warning(
        "DATA_ENCRYPTION_KEY не задан! Шифрование отключено. "
        "ВАЖНО: Задайте DATA_ENCRYPTION_KEY для защиты персональных данных!"
    )


# ============================================================================
# ПСЕВДОНИМИЗАЦИЯ (ХЭШИРОВАНИЕ ID)
# ============================================================================

def pseudonymize_id(user_id: int, context: str = "default") -> str:
    """Псевдонимизирует user_id через HMAC-SHA256.
    
    Args:
        user_id: Реальный Telegram user_id
        context: Контекст использования (для разных хэшей в разных местах)
        
    Returns:
        Псевдоним в формате "u_<hash[:16]>" (16 символов хэша)
        
    Note:
        - Один и тот же user_id всегда даёт один и тот же псевдоним
        - Невозможно восстановить user_id из псевдонима без соли
        - Разные контексты дают разные псевдонимы
    """
    message = f"{context}:{user_id}".encode()
    h = hmac.new(_HASH_SALT.encode(), message, hashlib.sha256)
    return f"u_{h.hexdigest()[:16]}"


def pseudonymize_chat_id(chat_id: int) -> str:
    """Псевдонимизирует chat_id."""
    return pseudonymize_id(chat_id, context="chat")


def create_lookup_hash(user_id: int, chat_id: int) -> str:
    """Создаёт хэш для поиска данных пользователя в чате.
    
    Используется как ключ в Redis вместо открытых ID.
    """
    message = f"lookup:{chat_id}:{user_id}".encode()
    h = hmac.new(_HASH_SALT.encode(), message, hashlib.sha256)
    return h.hexdigest()[:32]


# ============================================================================
# ШИФРОВАНИЕ ДАННЫХ
# ============================================================================

def encrypt_data(data: str) -> Optional[str]:
    """Шифрует строку данных.
    
    Args:
        data: Данные для шифрования
        
    Returns:
        Зашифрованная строка в base64 или None если шифрование отключено
    """
    if not _fernet:
        return None
    try:
        encrypted = _fernet.encrypt(data.encode())
        return encrypted.decode()
    except Exception as exc:
        log.error(f"Ошибка шифрования: {exc}")
        return None


def decrypt_data(encrypted: str) -> Optional[str]:
    """Расшифровывает данные.
    
    Args:
        encrypted: Зашифрованная строка
        
    Returns:
        Расшифрованные данные или None при ошибке
    """
    if not _fernet:
        return None
    try:
        decrypted = _fernet.decrypt(encrypted.encode())
        return decrypted.decode()
    except Exception as exc:
        log.error(f"Ошибка расшифровки: {exc}")
        return None


def encrypt_pii(data: Dict[str, Any]) -> Dict[str, Any]:
    """Шифрует персональные данные в словаре.
    
    Шифрует поля: id, username, first_name, last_name, full_name
    Оставляет: is_bot, updated_at
    
    ВАЖНО: user_id тоже шифруется, т.к. через него можно пробить человека
    """
    if not _fernet:
        return data
    
    result = data.copy()
    # Теперь шифруем и ID!
    pii_fields = ["id", "username", "first_name", "last_name", "full_name", "language_code"]
    
    for field in pii_fields:
        if field in result and result[field] is not None:
            value = result[field]
            # Проверяем, не зашифровано ли уже
            if isinstance(value, str) and value.startswith("enc:"):
                continue
            encrypted = encrypt_data(str(value))
            if encrypted:
                result[field] = f"enc:{encrypted}"
    
    return result


def decrypt_pii(data: Dict[str, Any]) -> Dict[str, Any]:
    """Расшифровывает персональные данные в словаре."""
    if not _fernet:
        return data
    
    result = data.copy()
    
    for key, value in result.items():
        if isinstance(value, str) and value.startswith("enc:"):
            decrypted = decrypt_data(value[4:])
            if decrypted:
                # Для id конвертируем обратно в int
                if key == "id":
                    try:
                        result[key] = int(decrypted)
                    except ValueError:
                        result[key] = decrypted
                else:
                    result[key] = decrypted
    
    return result


# ============================================================================
# ШИФРОВАНИЕ ИСТОРИИ ДИАЛОГОВ
# ============================================================================

def encrypt_history(history_data: str) -> Optional[str]:
    """Шифрует историю диалогов (JSON строку).
    
    Args:
        history_data: JSON строка с историей
        
    Returns:
        Зашифрованная строка с префиксом "enc:" или исходная если шифрование отключено
    """
    if not _fernet:
        return history_data
    
    encrypted = encrypt_data(history_data)
    if encrypted:
        return f"enc:{encrypted}"
    return history_data


def decrypt_history(encrypted_data: str) -> Optional[str]:
    """Расшифровывает историю диалогов.
    
    Args:
        encrypted_data: Зашифрованная строка (может быть с префиксом "enc:" или без)
        
    Returns:
        Расшифрованная JSON строка или исходная если не зашифрована
    """
    if not encrypted_data:
        return encrypted_data
    
    # Если не зашифровано — возвращаем как есть
    if not encrypted_data.startswith("enc:"):
        return encrypted_data
    
    if not _fernet:
        log.warning("Попытка расшифровать данные без ключа шифрования")
        return None
    
    decrypted = decrypt_data(encrypted_data[4:])
    return decrypted


# ============================================================================
# БЕЗОПАСНОЕ ЛОГИРОВАНИЕ
# ============================================================================

def safe_log_user(user_id: int, username: Optional[str] = None) -> str:
    """Возвращает безопасное представление пользователя для логов.
    
    Вместо реальных данных возвращает псевдоним.
    """
    pseudo = pseudonymize_id(user_id)
    if username:
        # Показываем только первые 2 символа username
        masked = username[:2] + "***" if len(username) > 2 else "***"
        return f"{pseudo} ({masked})"
    return pseudo


def safe_log_action(
    action_type: str,
    target_user_id: int,
    chat_id: int,
    admin_id: Optional[int] = None,
    reason: Optional[str] = None
) -> str:
    """Формирует безопасную строку для лога действия модерации."""
    target = pseudonymize_id(target_user_id)
    chat = pseudonymize_chat_id(chat_id)
    admin = pseudonymize_id(admin_id) if admin_id else "auto"
    
    # Обрезаем причину и убираем потенциальные PII
    safe_reason = ""
    if reason:
        # Убираем @username из причины
        import re
        safe_reason = re.sub(r'@\w+', '@***', reason)[:50]
    
    return f"[{action_type}] target={target} chat={chat} by={admin} reason={safe_reason}"


# ============================================================================
# ГЕНЕРАЦИЯ КЛЮЧЕЙ (для первоначальной настройки)
# ============================================================================

def generate_encryption_key() -> str:
    """Генерирует новый ключ шифрования Fernet.
    
    Используйте для первоначальной настройки:
    python -c "from app.security.data_protection import generate_encryption_key; print(generate_encryption_key())"
    """
    return Fernet.generate_key().decode()


def generate_hash_salt() -> str:
    """Генерирует новую соль для хэширования.
    
    Используйте для первоначальной настройки:
    python -c "from app.security.data_protection import generate_hash_salt; print(generate_hash_salt())"
    """
    return secrets.token_hex(32)


# ============================================================================
# БЕЗОПАСНОЕ УДАЛЕНИЕ ДАННЫХ
# ============================================================================

def secure_delete_keys(redis_client, keys: list) -> int:
    """Безопасно удаляет ключи из Redis с перезаписью.
    
    Перед удалением перезаписывает данные случайными байтами,
    чтобы затруднить восстановление из бэкапов/снапшотов.
    
    Args:
        redis_client: Redis клиент
        keys: Список ключей для удаления
        
    Returns:
        Количество удалённых ключей
    """
    deleted = 0
    for key in keys:
        try:
            # Перезаписываем случайными данными перед удалением
            redis_client.set(key, secrets.token_bytes(64), ex=1)
            redis_client.delete(key)
            deleted += 1
        except Exception as exc:
            log.error(f"Ошибка безопасного удаления ключа {key}: {exc}")
    return deleted


def anonymize_user_data(profile: Dict[str, Any]) -> Dict[str, Any]:
    """Анонимизирует профиль пользователя для экспорта/аналитики.
    
    Заменяет все PII на анонимные значения.
    """
    return {
        "id": pseudonymize_id(profile.get("id", 0)),
        "is_bot": profile.get("is_bot", False),
        "updated_at": profile.get("updated_at"),
        # Все остальные поля удаляются
    }


# ============================================================================
# ПРОВЕРКА КОНФИГУРАЦИИ
# ============================================================================

def check_security_config() -> Dict[str, Any]:
    """Проверяет конфигурацию безопасности.
    
    Returns:
        Словарь с результатами проверки
    """
    issues = []
    
    if not os.getenv("DATA_HASH_SALT"):
        issues.append("DATA_HASH_SALT не задан - используется временная соль")
    
    if not os.getenv("DATA_ENCRYPTION_KEY"):
        issues.append("DATA_ENCRYPTION_KEY не задан - шифрование отключено")
    
    if not os.getenv("WEBHOOK_SECRET_TOKEN"):
        issues.append("WEBHOOK_SECRET_TOKEN не задан - генерируется при каждом запуске")
    
    # Требуем наличие всех секретов для полной безопасности
    is_secure = (
        bool(os.getenv("DATA_HASH_SALT")) and 
        bool(os.getenv("DATA_ENCRYPTION_KEY")) and
        bool(os.getenv("WEBHOOK_SECRET_TOKEN"))
    )
    
    return {
        "encryption_enabled": _fernet is not None,
        "hash_salt_configured": bool(os.getenv("DATA_HASH_SALT")),
        "issues": issues,
        "secure": is_secure
    }
