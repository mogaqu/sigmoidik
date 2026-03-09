# Copyright (c) 2026 mogaqu
"""Быстрый переводчик через LLM."""

from typing import Optional

from app.llm.client import llm_request
from app.logging_config import log


def translate_text(chat_id: int, text: str, target_lang: str = "ru") -> Optional[str]:
    """
    Переводит текст на указанный язык.
    
    Args:
        chat_id: ID чата
        text: Текст для перевода
        target_lang: Целевой язык (ru, en, etc)
    
    Returns:
        Переведенный текст или None
    """
    lang_names = {
        "ru": "русский",
        "en": "английский",
        "es": "испанский",
        "fr": "французский",
        "de": "немецкий",
        "it": "итальянский",
        "ja": "японский",
        "ko": "корейский",
        "zh": "китайский",
    }
    
    target_name = lang_names.get(target_lang, target_lang)
    
    prompt = (
        f"Переведи следующий текст на {target_name}. "
        f"Отвечай ТОЛЬКО переводом, без пояснений:\n\n{text}"
    )
    
    try:
        response, _, _ = llm_request(chat_id, [{"text": prompt}], None)
        return response
    except Exception as exc:
        log.error(f"Translation error: {exc}")
        return None


def detect_language(text: str) -> str:
    """Определяет язык текста (простая эвристика)."""
    # Проверяем кириллицу
    cyrillic_count = sum(1 for c in text if '\u0400' <= c <= '\u04FF')
    if cyrillic_count > len(text) * 0.3:
        return "ru"
    
    # Проверяем японские символы
    japanese_count = sum(1 for c in text if '\u3040' <= c <= '\u309F' or '\u30A0' <= c <= '\u30FF')
    if japanese_count > 0:
        return "ja"
    
    # Проверяем китайские символы
    chinese_count = sum(1 for c in text if '\u4E00' <= c <= '\u9FFF')
    if chinese_count > 0:
        return "zh"
    
    # По умолчанию английский
    return "en"
