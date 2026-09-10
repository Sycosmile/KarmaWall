import logging
import tempfile
import unittest
from logging.handlers import RotatingFileHandler
from pathlib import Path

from logger import BACKUP_COUNT, LOGGER_NAME, MAX_LOG_BYTES, setup_logger


class TestLogger(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.log_path = Path(self.temp_dir.name) / "logs" / "karmawall.log"

    def test_logger_creates_log_directory_and_file(self):
        logger = setup_logger(self.log_path)
        logger.info("test message")
        for handler in logger.handlers:
            handler.flush()

        self.assertTrue(self.log_path.exists())
        self.assertIn("test message", self.log_path.read_text(encoding="utf-8"))

    def test_logger_has_rotating_file_handler(self):
        logger = setup_logger(self.log_path)

        file_handlers = [
            handler
            for handler in logger.handlers
            if isinstance(handler, RotatingFileHandler)
        ]

        self.assertEqual(len(file_handlers), 1)
        self.assertEqual(file_handlers[0].maxBytes, MAX_LOG_BYTES)
        self.assertEqual(file_handlers[0].backupCount, BACKUP_COUNT)

    def test_repeated_setup_does_not_duplicate_handlers(self):
        first = setup_logger(self.log_path)
        second = setup_logger(self.log_path)

        self.assertIs(first, second)
        self.assertEqual(len(second.handlers), 2)
        self.assertFalse(second.propagate)

    def tearDown(self):
        logger = logging.getLogger(LOGGER_NAME)
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
            handler.close()


if __name__ == "__main__":
    unittest.main()
