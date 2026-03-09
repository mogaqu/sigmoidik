# Copyright (c) 2026 mogaqu
import logging


def configure_logging() -> logging.Logger:
    logging.basicConfig(
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        level=logging.INFO,
    )
    return logging.getLogger("wizardbot")


log = configure_logging()


