# Copyright (c) 2026 mogaqu
import re
from typing import List

def strip_html_tags(text: str) -> str:
    clean = re.compile(r"<.*?>")
    return re.sub(clean, "", text)


def remove_ads(text: str) -> str:
    """Удаляет известные рекламные сообщения."""
    ad_patterns = [
        r"Need proxies cheaper than the market\?",
        r"https://op\.wtf",
        r"discord\.gg/airforce",
    ]
    for pattern in ad_patterns:
        text = re.sub(pattern, "", text, flags=re.I)
    return text.strip()


def sanitize_html_for_telegram(text: str) -> str:
    """Санитизирует HTML для безопасной отправки в Telegram (parse_mode=HTML).

    - Удаляет опасные теги (script, object, iframe и т.д.).
    - Для <a href="..."> оставляет только http(s) ссылки, иначе заменяет на #.
    - Снижает риск XSS при выводе ответов LLM.
    """
    if not text or not isinstance(text, str):
        return text
    # Удаляем script-блоки целиком
    text = re.sub(r"<script\b[^>]*>.*?</script>", "", text, flags=re.I | re.DOTALL)
    # Удаляем опасные теги (открывающие и закрывающие)
    for tag in ("script", "object", "embed", "iframe", "form", "input", "button", "style", "meta", "link"):
        text = re.sub(r"<" + tag + r"\b[^>]*>", "", text, flags=re.I)
        text = re.sub(r"</" + tag + r">", "", text, flags=re.I)
    # В href оставляем только http(s) и tg:// (Telegram), иначе подставляем #
    def _safe_href(match: re.Match) -> str:
        href = (match.group(2) or "").strip()
        if href.startswith("http://") or href.startswith("https://") or href.startswith("tg://"):
            return match.group(0)
        return '<a href="#">'
    text = re.sub(r'<a\s+([^>]*?)href\s*=\s*["\']([^"\']*)["\']([^>]*)>', _safe_href, text, flags=re.I)
    # Убираем javascript: и data: в оставшихся href (на случай другого порядка атрибутов)
    text = re.sub(r'href\s*=\s*["\']\s*javascript:[^"\']*["\']', 'href="#"', text, flags=re.I)
    text = re.sub(r'href\s*=\s*["\']\s*data:[^"\']*["\']', 'href="#"', text, flags=re.I)
    return text


def answer_size_prompt(size: str) -> str:
    return {
        "small": "Кратко:",
        "medium": "Ответь развёрнуто:",
        "large": "Ответь максимально подробно:",
    }.get(size, "")


def split_long_message(text: str, max_length: int = 4096) -> List[str]:
    if len(text) <= max_length:
        return [text]
    parts, current = [], ""
    for line in text.split("\n"):
        if len(current) + len(line) + 1 <= max_length:
            current += line + "\n"
        else:
            if current:
                parts.append(current.strip())
            current = line
    if current:
        parts.append(current.strip())
    return parts
