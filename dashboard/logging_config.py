"""
Structured JSON logging configuration.

Extracted from api_server.py lines 158-236.
"""

import json
import os
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def format(self, record):
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }

        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)

        for attr in ('request_id', 'user', 'endpoint', 'method', 'status_code',
                     'duration_ms', 'remote_addr'):
            if hasattr(record, attr):
                log_entry[attr] = getattr(record, attr)

        return json.dumps(log_entry)


def configure_logging(app=None):
    """Configure structured JSON logging for production.

    Args:
        app: Optional Flask app whose logger will be updated.

    Returns:
        Configured logger instance.
    """
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    log_format = os.getenv('LOG_FORMAT', 'json')
    log_file = os.getenv('LOG_FILE', '')

    logger = logging.getLogger('networkops')
    logger.setLevel(getattr(logging, log_level, logging.INFO))
    logger.handlers = []

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    if log_format == 'json':
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))

    logger.addHandler(console_handler)

    # File handler (if configured)
    if log_file:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JSONFormatter())
        logger.addHandler(file_handler)

    # Sync Flask's logger
    if app is not None:
        app.logger.handlers = logger.handlers
        app.logger.setLevel(logger.level)

    return logger
