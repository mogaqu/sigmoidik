# Copyright (c) 2026 mogaqu
import asyncio
import time

from telegram.constants import ParseMode
from telegram.error import BadRequest
from telegram.ext import CallbackContext

from app.llm.client import check_available_models, llm_request
from app.logging_config import log
from app.state import configs
from app.storage.redis_store import persist_chat_data
from app.utils.text import split_long_message


async def check_models_job(context: CallbackContext):
    await asyncio.get_running_loop().run_in_executor(None, check_available_models)


async def autopost_job(context: CallbackContext):
    for chat_id, cfg in list(configs.items()):
        if not (
            cfg.autopost_enabled
            and cfg.new_msg_counter >= cfg.min_messages
            and time.time() - cfg.last_post_ts > cfg.interval
        ):
            continue
        # Ограничение для предотвращения DoS через большое количество сообщений
        msg_count = min(cfg.new_msg_counter, 1000)
        prompt = f"Сделай краткий дайджест последних {msg_count} сообщений чата. Выдели основные темы."
        log.info(f"Autopost in chat {chat_id}")
        try:
            summary, model_used, _ = await asyncio.get_running_loop().run_in_executor(
                None, llm_request, chat_id, [{"text": prompt}], cfg.llm_provider or None
            )
            if summary:
                model_display = model_used.replace("gemini-", "").replace("-latest", "").title()
                message_text = f"📰 <b>Автодайджест ({model_display}):</b>\n{summary}"
                for chunk in split_long_message(message_text):
                    try:
                        await context.bot.send_message(chat_id, chunk, parse_mode=ParseMode.HTML)
                    except BadRequest:
                        await context.bot.send_message(chat_id, chunk)
                cfg.last_post_ts, cfg.new_msg_counter = time.time(), 0
                await persist_chat_data(chat_id)
        except Exception as exc:
            log.error(f"Autopost failed for chat {chat_id}: {exc}")


