"""
Logging setup for KarmaWall.

Firewall decisions are written to both the console and a rotating audit
log so long-running sessions do not grow the log file without bound.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


LOGGER_NAME = "firewall"
MAX_LOG_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 3


def setup_logger(log_file):
    """Create and return the KarmaWall logger.

    Existing KarmaWall handlers are replaced so repeated setup calls do not
    duplicate every log message. Other loggers and the root logger are left
    untouched.
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=MAX_LOG_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
