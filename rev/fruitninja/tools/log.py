import colorama
from pathlib import Path
import logging

log = logging.getLogger("riscv")
log.setLevel(logging.INFO)
channel = logging.StreamHandler()


class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors and count warning / errors"""

    ERROR = (
        colorama.Fore.WHITE
        + colorama.Back.RED
        + "ERROR"
        + colorama.Fore.RESET
        + colorama.Back.RESET
    )
    WARNING = colorama.Fore.YELLOW + "!" + colorama.Fore.RESET
    INFO = colorama.Fore.BLUE + "*" + colorama.Fore.RESET
    DEBUG = colorama.Fore.GREEN + "+" + colorama.Fore.RESET

    FORMATS = {
        logging.ERROR: f"[{ERROR}] %(msg)s",
        logging.WARNING: f"[{WARNING}] %(msg)s",
        logging.INFO: f"[{INFO}] %(msg)s",
        logging.DEBUG: f"[{DEBUG}] %(msg)s",
        "DEFAULT": "%(msg)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


channel.setFormatter(CustomFormatter())
log.addHandler(channel)


def info(msg: str):
    log.info(msg)


def warn(msg: str):
    log.warning(msg)


def error(msg: str):
    log.error(msg)
    exit(1)
