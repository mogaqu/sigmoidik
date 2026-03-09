# Copyright (c) 2025 sprowii
"""Rate limiting middleware для защиты от спама."""

import time
from typing import Dict, Tuple
from app.storage.redis_store import redis_client
from app.logging_config import log

# Redis ключи
RATE_LIMIT_PREFIX = "rl:"
WEB_RATE_LIMIT_PREFIX = "wrl:"
LOGIN_RATE_LIMIT_PREFIX = "lrl:"

# Настройки
MAX_REQUESTS_PER_MINUTE = 10
MAX_REQUESTS_PER_HOUR = 100

# Настройки для веб-запросов
WEB_MAX_REQUESTS_PER_MINUTE = 30
WEB_MAX_REQUESTS_PER_HOUR = 300

# Настройки для login (более строгие для защиты от brute-force)
LOGIN_MAX_ATTEMPTS_PER_MINUTE = 3
LOGIN_MAX_ATTEMPTS_PER_HOUR = 10

BLOCK_DURATION_SEC = 3600  # 1 час блокировки


def check_rate_limit(user_id: int) -> Tuple[bool, str]:
    """
    Проверяет, не превышен ли лимит запросов через Redis.
    """
    key = f"{RATE_LIMIT_PREFIX}{user_id}"
    
    try:
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, 3600)  # Сброс через час
            
        if count > MAX_REQUESTS_PER_HOUR:
            return False, "⏱️ Превышен часовой лимит запросов."
        
        # Проверка минутного лимита через простой ключ с TTL
        min_key = f"{key}:min"
        min_count = redis_client.incr(min_key)
        if min_count == 1:
            redis_client.expire(min_key, 60)
        
        if min_count > MAX_REQUESTS_PER_MINUTE:
            return False, "⏱️ Слишком много запросов. Подожди минуту."
            
        return True, ""
    except Exception as e:
        log.error(f"Redis rate limit error: {e}")
        return True, ""  # Fail-open


def get_user_stats(user_id: int) -> Dict[str, int]:
    """Возвращает статистику пользователя."""
    key = f"{RATE_LIMIT_PREFIX}{user_id}"
    try:
        count = int(redis_client.get(key) or 0)
        return {"requests": count}
    except Exception as e:
        log.error(f"Error getting stats: {e}")
        return {"requests": 0}


def check_web_rate_limit(ip_address: str) -> Tuple[bool, str]:
    """
    Проверяет rate limit для веб-запросов по IP через Redis.
    """
    key = f"{WEB_RATE_LIMIT_PREFIX}{ip_address}"
    
    try:
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, 3600)
            
        if count > WEB_MAX_REQUESTS_PER_HOUR:
            return False, "Hourly limit exceeded."
            
        min_key = f"{key}:min"
        min_count = redis_client.incr(min_key)
        if min_count == 1:
            redis_client.expire(min_key, 60)
        
        if min_count > WEB_MAX_REQUESTS_PER_MINUTE:
            return False, "Too many requests. Please wait."
            
        return True, ""
    except Exception as e:
        log.error(f"Redis web rate limit error: {e}")
        return True, ""


def check_login_rate_limit(ip_address: str) -> Tuple[bool, str]:
    """
    Проверяет rate limit для login попыток через Redis.
    """
    key = f"{LOGIN_RATE_LIMIT_PREFIX}{ip_address}"
    block_key = f"{key}:blocked"
    
    try:
        if redis_client.exists(block_key):
            ttl = redis_client.ttl(block_key)
            return False, f"IP temporarily blocked. Try again in {ttl // 60} minutes."
            
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, 3600)
            
        if count > LOGIN_MAX_ATTEMPTS_PER_HOUR:
            redis_client.setex(block_key, BLOCK_DURATION_SEC, "1")
            return False, "Too many login attempts. IP blocked for 1 hour."
            
        min_key = f"{key}:min"
        min_count = redis_client.incr(min_key)
        if min_count == 1:
            redis_client.expire(min_key, 60)
        
        if min_count > LOGIN_MAX_ATTEMPTS_PER_MINUTE:
            if min_count >= LOGIN_MAX_ATTEMPTS_PER_MINUTE * 2:
                redis_client.setex(block_key, BLOCK_DURATION_SEC, "1")
                return False, "Too many failed attempts. IP blocked for 1 hour."
            return False, "Too many login attempts. Please wait 1 minute."
            
        return True, ""
    except Exception as e:
        log.error(f"Redis login rate limit error: {e}")
        return True, ""
