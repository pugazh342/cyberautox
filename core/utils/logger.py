# core/utils/logger.py
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path

# Define custom log levels
SUCCESS_LEVEL_NUM = 25  # Between INFO (20) and WARNING (30)
logging.addLevelName(SUCCESS_LEVEL_NUM, 'SUCCESS')

def success(self, message, *args, **kws):
    if self.isEnabledFor(SUCCESS_LEVEL_NUM):
        self._log(SUCCESS_LEVEL_NUM, message, args, **kws)

logging.Logger.success = success # Add the success method to the Logger class

class CyberLogger:
    def __init__(self, name='CyberAutoX', log_file='cyberautox.log', level=logging.INFO, max_bytes=10*1024*1024, backup_count=5):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.propagate = False # Prevent messages from being passed to the root logger

        # Ensure handlers are not duplicated if CyberLogger is initialized multiple times
        if not self.logger.handlers:
            # Console Handler
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)

            # File Handler
            log_dir = Path(__file__).parent.parent.parent / "outputs" / "logs"
            log_dir.mkdir(parents=True, exist_ok=True) # Ensure the logs directory exists
            log_file_path = log_dir / log_file

            file_handler = RotatingFileHandler(
                log_file_path,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)

    def debug(self, message):
        self.logger.debug(message)

    def info(self, message):
        self.logger.info(message)
    
    def success(self, message):
        """Logs a message with the custom SUCCESS level."""
        self.logger.success(message) # Use the dynamically added method

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def critical(self, message):
        self.logger.critical(message)

# Example usage (for testing)
if __name__ == '__main__':
    logger = CyberLogger()
    logger.debug("This is a debug message.")
    logger.info("This is an info message.")
    logger.success("This is a success message!")
    logger.warning("This is a warning message.")
    logger.error("This is an error message.")
    logger.critical("This is a critical message.")
    
    print(f"Log file created at: {Path(__file__).parent.parent.parent / 'outputs' / 'logs' / 'cyberautox.log'}")