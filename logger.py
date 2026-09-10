"""
Logging setup. Every decision the firewall makes gets written here —
this is your audit trail, and it's what you'd actually check after a
probing session to see everything your machine tried to talk to.
"""

import logging


def setup_logger(log_file):
    logger = logging.getLogger("firewall")
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)

    logger.handlers.clear()
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
