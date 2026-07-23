import logging
import sys
from pathlib import Path
from typing import Optional

_RESET = "\033[0m"
_BOLD  = "\033[1m"

_LEVEL_COLORS = {
    "DEBUG":    "\033[36m",
    "INFO":     "\033[32m",
    "WARNING":  "\033[33m",
    "ERROR":    "\033[31m",
    "CRITICAL": "\033[35m",
}

_LEVEL_WIDTH = 8
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_LOG_FORMAT  = "%(asctime)s  %(levelname)s  %(name)-28s  %(message)s"

_configured_loggers: set[str] = set()


class _ColoredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        record = logging.makeLogRecord(record.__dict__)
        color  = _LEVEL_COLORS.get(record.levelname, _RESET)
        padded = record.levelname.ljust(_LEVEL_WIDTH)
        record.levelname = f"{color}{_BOLD}{padded}{_RESET}"
        return super().format(record)


class _PlainFormatter(logging.Formatter):
    pass


def setup_logger(
    name: str = "shieldforge",
    level: int = logging.INFO,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Return a named logger with coloured console output.

    Args:
        name:     Logger name.
        level:    Minimum log level.
        log_file: Optional path to a plain-text log file.

    Returns:
        logging.Logger
    """
    logger = logging.getLogger(name)

    if name in _configured_loggers:
        return logger

    _configured_loggers.add(name)
    logger.setLevel(level)
    logger.propagate = False

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(
        _ColoredFormatter(fmt=_LOG_FORMAT, datefmt=_DATE_FORMAT)
    )
    logger.addHandler(console_handler)

    if log_file:
        _add_file_handler(logger, log_file)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Retrieve a logger by name.

    Args:
        name: Dotted logger name.

    Returns:
        logging.Logger
    """
    return logging.getLogger(name)


def set_debug_mode(enable: bool = True) -> None:
    """Toggle DEBUG level on the root ShieldForge logger.

    Args:
        enable: True for DEBUG, False for INFO.
    """
    level = logging.DEBUG if enable else logging.INFO
    root  = logging.getLogger("shieldforge")
    root.setLevel(level)
    for handler in root.handlers:
        handler.setLevel(level)


def add_file_logging(file_path: str, level: int = logging.DEBUG) -> None:
    """Attach a file handler to the root ShieldForge logger.

    Args:
        file_path: Destination file path.
        level:     Minimum level for file output.
    """
    root = logging.getLogger("shieldforge")
    _add_file_handler(root, file_path, level)


def _add_file_handler(
    logger: logging.Logger,
    file_path: str,
    level: int = logging.DEBUG,
) -> None:
    try:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(
            _PlainFormatter(fmt=_LOG_FORMAT, datefmt=_DATE_FORMAT)
        )
        logger.addHandler(file_handler)
    except OSError as exc:
        logger.warning("Could not open log file '%s': %s", file_path, exc)