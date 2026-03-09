# Copyright (c) 2026 mogaqu
"""Простой кэш для ответов LLM."""

import hashlib
import time
from typing import Dict, Optional, Tuple

from app.logging_config import log

# Хранилище: {hash: (response, model, timestamp)}
_cache: Dict[str, Tuple[str, str, float]] = {}

CACHE_TTL = 3600  # 1 час
MAX_CACHE_SIZE = 1000
CLEANUP_INTERVAL = 600  # Очистка каждые 10 минут
_last_cleanup = time.time()


def _make_cache_key(chat_id: int, prompt: str) -> str:
    """Создает хэш для кэша."""
    # Нормализуем промпт (убираем лишние пробелы)
    normalized = " ".join(prompt.lower().split())
    key_str = f"{chat_id}:{normalized}"
    return hashlib.sha256(key_str.encode()).hexdigest()[:16]


def _cleanup_cache():
    """Удаляет устаревшие записи."""
    global _last_cleanup
    now = time.time()
    
    if now - _last_cleanup < CLEANUP_INTERVAL:
        return
    
    cutoff = now - CACHE_TTL
    to_remove = [key for key, (_, _, ts) in _cache.items() if ts < cutoff]
    
    for key in to_remove:
        del _cache[key]
    
    # Если кэш слишком большой, удаляем самые старые
    if len(_cache) > MAX_CACHE_SIZE:
        sorted_items = sorted(_cache.items(), key=lambda x: x[1][2])
        to_remove_count = len(_cache) - MAX_CACHE_SIZE
        for key, _ in sorted_items[:to_remove_count]:
            del _cache[key]
    
    _last_cleanup = now
    if to_remove:
        log.debug(f"Cleaned up {len(to_remove)} cache entries")


def get_cached_response(chat_id: int, prompt: str) -> Optional[Tuple[str, str]]:
    """
    Получает закэшированный ответ.
    
    Returns:
        (response, model) или None если не найдено
    """
    _cleanup_cache()
    
    key = _make_cache_key(chat_id, prompt)
    
    if key not in _cache:
        return None
    
    response, model, timestamp = _cache[key]
    
    # Проверяем, не устарел ли кэш
    if time.time() - timestamp > CACHE_TTL:
        del _cache[key]
        return None
    
    log.info(f"Cache hit for chat {chat_id}")
    return response, model


def cache_response(chat_id: int, prompt: str, response: str, model: str):
    """Сохраняет ответ в кэш."""
    _cleanup_cache()
    
    key = _make_cache_key(chat_id, prompt)
    _cache[key] = (response, model, time.time())
    log.debug(f"Cached response for chat {chat_id}, cache size: {len(_cache)}")


def get_cache_stats() -> Dict[str, int]:
    """Возвращает статистику кэша."""
    return {
        "size": len(_cache),
        "max_size": MAX_CACHE_SIZE,
        "ttl_seconds": CACHE_TTL,
    }
