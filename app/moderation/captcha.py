# Copyright (c) 2026 mogaqu

import asyncio
import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple, List

from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup, User
from telegram.error import TelegramError

from app.logging_config import log
from app.security.data_protection import pseudonymize_id, pseudonymize_chat_id
from app.moderation.models import Captcha, ChatModSettings
from app.moderation.storage import redis_client

# Redis key prefixes
CAPTCHA_PREFIX = "captcha:"
PENDING_CAPTCHA_PREFIX = "pending_captcha:"

# TTL for pending captcha (max 10 minutes)
MAX_CAPTCHA_TTL_SEC = 600


class CaptchaDifficulty(str, Enum):
    """Уровни сложности captcha."""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


@dataclass
class CaptchaChallenge:
    """Сгенерированный captcha challenge."""
    question: str
    answer: str
    keyboard: Optional[InlineKeyboardMarkup] = None


class CaptchaProvider:
    """Провайдер captcha для проверки новых участников.
    
    Requirement 6.1: Generate simple math or button captcha challenge
    
    Сложность:
    - Easy: простое сложение (2+3)
    - Medium: сложение двузначных чисел (12+7)
    - Hard: умножение (23*4)
    """
    
    def __init__(self, settings: Optional[ChatModSettings] = None):
        self.settings = settings
    
    def generate(self, difficulty: str = "easy") -> CaptchaChallenge:
        """Сгенерировать captcha challenge.
        
        Requirement 6.1: simple math or button captcha challenge
        
        Args:
            difficulty: Уровень сложности (easy, medium, hard)
            
        Returns:
            CaptchaChallenge с вопросом, ответом и клавиатурой
        """
        difficulty = difficulty.lower()
        
        if difficulty == "hard":
            return self._generate_hard()
        elif difficulty == "medium":
            return self._generate_medium()
        else:
            return self._generate_easy()
    
    def _generate_easy(self) -> CaptchaChallenge:
        """Easy: простое сложение однозначных чисел (2+3=5)."""
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        answer = a + b
        question = f"{a} + {b} = ?"
        
        # Генерируем варианты ответов для кнопок
        keyboard = self._generate_answer_keyboard(answer, min_val=2, max_val=18)
        
        return CaptchaChallenge(
            question=question,
            answer=str(answer),
            keyboard=keyboard
        )
    
    def _generate_medium(self) -> CaptchaChallenge:
        """Medium: сложение с двузначными числами (12+7=19)."""
        a = random.randint(10, 30)
        b = random.randint(1, 20)
        answer = a + b
        question = f"{a} + {b} = ?"
        
        # Генерируем варианты ответов для кнопок
        keyboard = self._generate_answer_keyboard(answer, min_val=11, max_val=50)
        
        return CaptchaChallenge(
            question=question,
            answer=str(answer),
            keyboard=keyboard
        )
    
    def _generate_hard(self) -> CaptchaChallenge:
        """Hard: умножение (23*4=92)."""
        a = random.randint(10, 30)
        b = random.randint(2, 9)
        answer = a * b
        question = f"{a} × {b} = ?"
        
        # Генерируем варианты ответов для кнопок
        keyboard = self._generate_answer_keyboard(answer, min_val=20, max_val=270)
        
        return CaptchaChallenge(
            question=question,
            answer=str(answer),
            keyboard=keyboard
        )
    
    def _generate_answer_keyboard(
        self,
        correct_answer: int,
        min_val: int,
        max_val: int,
        num_options: int = 4
    ) -> InlineKeyboardMarkup:
        """Генерирует клавиатуру с вариантами ответов.
        
        Args:
            correct_answer: Правильный ответ
            min_val: Минимальное значение для неправильных ответов
            max_val: Максимальное значение для неправильных ответов
            num_options: Количество вариантов (включая правильный)
            
        Returns:
            InlineKeyboardMarkup с кнопками ответов
        """
        options = {correct_answer}
        
        # Генерируем неправильные ответы близкие к правильному
        attempts = 0
        while len(options) < num_options and attempts < 100:
            # Генерируем ответ близкий к правильному (±20%)
            delta = max(1, int(correct_answer * 0.3))
            wrong = correct_answer + random.randint(-delta, delta)
            
            # Убеждаемся что ответ в допустимом диапазоне и не равен правильному
            if min_val <= wrong <= max_val and wrong != correct_answer:
                options.add(wrong)
            attempts += 1
        
        # Если не хватает вариантов, добавляем случайные
        while len(options) < num_options:
            wrong = random.randint(min_val, max_val)
            if wrong != correct_answer:
                options.add(wrong)
        
        # Перемешиваем и создаём кнопки
        options_list = sorted(list(options))
        random.shuffle(options_list)
        
        buttons = [
            InlineKeyboardButton(
                text=str(opt),
                callback_data=f"captcha:{opt}"
            )
            for opt in options_list
        ]
        
        # Располагаем кнопки в ряд
        return InlineKeyboardMarkup([buttons])
    
    def verify(self, user_answer: str, correct_answer: str) -> bool:
        """Проверить ответ пользователя.
        
        Args:
            user_answer: Ответ пользователя
            correct_answer: Правильный ответ
            
        Returns:
            True если ответ правильный
        """
        return user_answer.strip() == correct_answer.strip()



class CaptchaManager:
    """Менеджер captcha для управления проверками пользователей.
    
    Отвечает за:
    - Создание и хранение captcha challenges
    - Отслеживание таймаутов
    - Применение действий при провале (kick/mute)
    """
    
    def __init__(self, bot: Bot, settings: Optional[ChatModSettings] = None):
        self.bot = bot
        self.settings = settings
        self.provider = CaptchaProvider(settings)
        # Словарь для хранения задач таймаута: {(chat_id, user_id): asyncio.Task}
        self._timeout_tasks: Dict[Tuple[int, int], asyncio.Task] = {}
    
    def _get_captcha_key(self, chat_id: int, user_id: int) -> str:
        """Получить ключ Redis для captcha."""
        return f"{CAPTCHA_PREFIX}{chat_id}:{user_id}"
    
    def _get_pending_key(self, chat_id: int, user_id: int) -> str:
        """Получить ключ Redis для pending captcha."""
        return f"{PENDING_CAPTCHA_PREFIX}{chat_id}:{user_id}"
    
    async def create_captcha(
        self,
        chat_id: int,
        user: User,
        settings: ChatModSettings
    ) -> Optional[Captcha]:
        """Создать captcha для нового пользователя.
        
        Requirement 6.1: Send a simple math or button captcha challenge
        
        Args:
            chat_id: ID чата
            user: Пользователь для проверки
            settings: Настройки модерации чата
            
        Returns:
            Созданный Captcha объект или None при ошибке
        """
        # Генерируем challenge
        challenge = self.provider.generate(settings.captcha_difficulty)
        
        # Создаём объект Captcha
        captcha = Captcha.create(
            chat_id=chat_id,
            user_id=user.id,
            question=challenge.question,
            answer=challenge.answer,
            timeout_sec=settings.captcha_timeout_sec
        )
        
        # Сохраняем в Redis
        try:
            import json
            from dataclasses import asdict
            
            key = self._get_captcha_key(chat_id, user.id)
            data = asdict(captcha)
            redis_client.setex(
                key,
                settings.captcha_timeout_sec + 60,  # +60 сек запас
                json.dumps(data, ensure_ascii=False)
            )
        except Exception as exc:
            log.error(f"Не удалось сохранить captcha в Redis: {exc}")
            return None
        
        # Отправляем сообщение с captcha
        try:
            username = user.first_name or user.username or "Пользователь"
            message_text = (
                f"👋 Привет, <b>{username}</b>!\n\n"
                f"🔐 Для входа в чат реши простую задачу:\n\n"
                f"<b>{challenge.question}</b>\n\n"
                f"⏱ У тебя {settings.captcha_timeout_sec} секунд."
            )
            
            sent_message = await self.bot.send_message(
                chat_id=chat_id,
                text=message_text,
                reply_markup=challenge.keyboard,
                parse_mode="HTML"
            )
            
            # Сохраняем message_id для последующего удаления
            captcha.message_id = sent_message.message_id
            
            # Обновляем в Redis с message_id
            data = asdict(captcha)
            redis_client.setex(
                key,
                settings.captcha_timeout_sec + 60,
                json.dumps(data, ensure_ascii=False)
            )
            
            log.info(f"Captcha отправлена пользователю {pseudonymize_id(user.id)} в чате {pseudonymize_chat_id(chat_id)}")
            
        except TelegramError as exc:
            log.error(f"Не удалось отправить captcha: {exc}")
            return None
        
        # Запускаем таймер таймаута
        await self._start_timeout_task(chat_id, user.id, settings)
        
        return captcha
    
    async def _start_timeout_task(
        self,
        chat_id: int,
        user_id: int,
        settings: ChatModSettings
    ) -> None:
        """Запустить задачу таймаута для captcha.
        
        Requirement 6.2: Kick user if they fail to complete captcha within timeout
        """
        # Отменяем предыдущую задачу если есть
        task_key = (chat_id, user_id)
        if task_key in self._timeout_tasks:
            self._timeout_tasks[task_key].cancel()
        
        # Создаём новую задачу
        task = asyncio.create_task(
            self._handle_timeout(chat_id, user_id, settings)
        )
        self._timeout_tasks[task_key] = task
    
    async def _handle_timeout(
        self,
        chat_id: int,
        user_id: int,
        settings: ChatModSettings
    ) -> None:
        """Обработать таймаут captcha.
        
        Requirement 6.2: Apply configured fail action (kick/mute) on timeout
        """
        try:
            # Ждём таймаут
            await asyncio.sleep(settings.captcha_timeout_sec)
            
            # Проверяем, не была ли captcha уже решена
            captcha = await self.get_captcha(chat_id, user_id)
            if captcha is None:
                # Captcha уже решена или удалена
                return
            
            log.info(f"Captcha таймаут для пользователя {pseudonymize_id(user_id)} в чате {pseudonymize_chat_id(chat_id)}")
            
            # Удаляем сообщение с captcha
            if captcha.message_id:
                try:
                    await self.bot.delete_message(chat_id=chat_id, message_id=captcha.message_id)
                except TelegramError:
                    pass
            
            # Применяем действие при провале
            if settings.captcha_fail_action == "kick":
                try:
                    await self.bot.ban_chat_member(chat_id=chat_id, user_id=user_id)
                    # Сразу разбаниваем чтобы пользователь мог вернуться
                    await self.bot.unban_chat_member(chat_id=chat_id, user_id=user_id)
                    log.info(f"Пользователь {pseudonymize_id(user_id)} кикнут из чата {pseudonymize_chat_id(chat_id)} за провал captcha")
                except TelegramError as exc:
                    log.error(f"Не удалось кикнуть пользователя {pseudonymize_id(user_id)}: {exc}")
            
            elif settings.captcha_fail_action == "mute":
                try:
                    # Мутим на 24 часа
                    until_date = int(time.time()) + 86400
                    await self.bot.restrict_chat_member(
                        chat_id=chat_id,
                        user_id=user_id,
                        permissions={"can_send_messages": False},
                        until_date=until_date
                    )
                    log.info(f"Пользователь {pseudonymize_id(user_id)} замучен в чате {pseudonymize_chat_id(chat_id)} за провал captcha")
                except TelegramError as exc:
                    log.error(f"Не удалось замутить пользователя {pseudonymize_id(user_id)}: {exc}")
            
            # Удаляем captcha из Redis
            await self.remove_captcha(chat_id, user_id)
            
            # Логируем действие модерации
            try:
                from app.moderation.storage import save_mod_action_async
                from app.moderation.models import ModAction
                
                action = ModAction.create(
                    chat_id=chat_id,
                    action_type=settings.captcha_fail_action,
                    target_user_id=user_id,
                    reason="Провал captcha (таймаут)",
                    admin_id=None,
                    auto=True
                )
                await save_mod_action_async(action)
            except Exception as exc:
                log.error(f"Не удалось залогировать действие captcha: {exc}")
            
        except asyncio.CancelledError:
            # Задача отменена (captcha решена)
            pass
        except Exception as exc:
            log.error(f"Ошибка обработки таймаута captcha: {exc}")
        finally:
            # Удаляем задачу из словаря
            task_key = (chat_id, user_id)
            self._timeout_tasks.pop(task_key, None)
    
    async def get_captcha(self, chat_id: int, user_id: int) -> Optional[Captcha]:
        """Получить активную captcha для пользователя."""
        import json
        
        key = self._get_captcha_key(chat_id, user_id)
        try:
            raw = redis_client.get(key)
            if not raw:
                return None
            
            data = json.loads(raw)
            return Captcha(**data)
        except Exception as exc:
            log.error(f"Ошибка получения captcha: {exc}")
            return None
    
    async def verify_answer(
        self,
        chat_id: int,
        user_id: int,
        answer: str
    ) -> bool:
        """Проверить ответ пользователя на captcha.
        
        Requirement 6.3: Grant full chat permissions on success
        
        Args:
            chat_id: ID чата
            user_id: ID пользователя
            answer: Ответ пользователя
            
        Returns:
            True если ответ правильный
        """
        captcha = await self.get_captcha(chat_id, user_id)
        if captcha is None:
            return False
        
        is_correct = self.provider.verify(answer, captcha.answer)
        
        if is_correct:
            # Отменяем таймаут
            task_key = (chat_id, user_id)
            if task_key in self._timeout_tasks:
                self._timeout_tasks[task_key].cancel()
                self._timeout_tasks.pop(task_key, None)
            
            # Удаляем сообщение с captcha
            if captcha.message_id:
                try:
                    await self.bot.delete_message(chat_id=chat_id, message_id=captcha.message_id)
                except TelegramError:
                    pass
            
            # Удаляем captcha из Redis
            await self.remove_captcha(chat_id, user_id)
            
            log.info(f"Пользователь {pseudonymize_id(user_id)} успешно прошёл captcha в чате {pseudonymize_chat_id(chat_id)}")
        
        return is_correct
    
    async def remove_captcha(self, chat_id: int, user_id: int) -> None:
        """Удалить captcha из Redis."""
        key = self._get_captcha_key(chat_id, user_id)
        try:
            redis_client.delete(key)
        except Exception as exc:
            log.error(f"Ошибка удаления captcha: {exc}")
    
    def has_pending_captcha(self, chat_id: int, user_id: int) -> bool:
        """Проверить, есть ли у пользователя активная captcha."""
        key = self._get_captcha_key(chat_id, user_id)
        try:
            return redis_client.exists(key) > 0
        except Exception:
            return False


# Вспомогательные функции для использования без создания экземпляра класса

def check_pending_captcha(chat_id: int, user_id: int) -> bool:
    """Проверить, есть ли у пользователя активная captcha.
    
    Standalone функция для использования без CaptchaManager.
    """
    key = f"{CAPTCHA_PREFIX}{chat_id}:{user_id}"
    try:
        return redis_client.exists(key) > 0
    except Exception:
        return False


async def get_pending_captcha(chat_id: int, user_id: int) -> Optional[Captcha]:
    """Получить активную captcha для пользователя.
    
    Standalone функция для использования без CaptchaManager.
    """
    import json
    
    key = f"{CAPTCHA_PREFIX}{chat_id}:{user_id}"
    try:
        raw = redis_client.get(key)
        if not raw:
            return None
        
        data = json.loads(raw)
        return Captcha(**data)
    except Exception as exc:
        log.error(f"Ошибка получения captcha: {exc}")
        return None
