# Copyright (c) 2026 mogaqu
"""Security-related helpers.

Модули:
- privacy: Текст политики конфиденциальности
- data_protection: Шифрование и псевдонимизация данных
"""
from app.security.data_protection import (
    check_security_config,
    encrypt_data,
    decrypt_data,
    encrypt_pii,
    decrypt_pii,
    encrypt_history,
    decrypt_history,
    pseudonymize_id,
    pseudonymize_chat_id,
    safe_log_user,
    safe_log_action,
    generate_encryption_key,
    generate_hash_salt,
    secure_delete_keys,
    anonymize_user_data,
)

__all__ = [
    "check_security_config",
    "encrypt_data",
    "decrypt_data",
    "encrypt_pii",
    "decrypt_pii",
    "encrypt_history",
    "decrypt_history",
    "pseudonymize_id",
    "pseudonymize_chat_id",
    "safe_log_user",
    "safe_log_action",
    "generate_encryption_key",
    "generate_hash_salt",
    "secure_delete_keys",
    "anonymize_user_data",
]


