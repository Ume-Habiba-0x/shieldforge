"""ShieldForge — Framework engine."""

import importlib
import inspect
import logging
import pkgutil

from core.context import Context, Config
from core.models import ScanResult
from modules.base import BaseScanner
from utils.http_client import HTTPClient
from utils.logger import setup_logger

logger = setup_logger("shieldforge")


class Engine:
    """ShieldForge orchestrator."""

    def __init__(self, config: Config):
        self.config = config
        self.context = Context(config=config)
        self.context.http_client = HTTPClient(
            timeout=config.timeout,
            proxy=config.proxy,
            user_agent=config.user_agent,
            verify_ssl=config.verify_ssl
        )
        self.scanners = []

    def discover_scanners(self):
        scanner_classes = []
        import modules
        for _, module_name, _ in pkgutil.iter_modules(modules.__path__):
            if module_name == "base":
                continue
            try:
                module = importlib.import_module(f"modules.{module_name}")
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (issubclass(obj, BaseScanner) and
                        obj is not BaseScanner and
                        not inspect.isabstract(obj)):
                        scanner_classes.append(obj)
            except Exception as e:
                logger.warning("Failed to import %s: %s", module_name, e)
        return scanner_classes

    def load_scanners(self, scanner_names: list = None):
        scanner_classes = self.discover_scanners()
        for scanner_class in scanner_classes:
            scanner = scanner_class()
            if scanner_names is None or scanner.name in scanner_names:
                self.scanners.append(scanner)
                logger.info("Loaded: %s", scanner.name)

    def run(self) -> Context:
        logger.info("ShieldForge scanning %s", self.config.target_url)
        for scanner in self.scanners:
            logger.info("Running: %s", scanner.name)
            result = scanner.run(self.context)
            self.context.add_result(result)
            logger.info("%s: %d findings", scanner.name, len(result.findings))
        return self.context
