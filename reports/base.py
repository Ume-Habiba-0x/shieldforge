"""ShieldForge — Abstract base for report generators."""

from abc import ABC, abstractmethod

from core.context import Context


class BaseReport(ABC):
    @property
    @abstractmethod
    def format_name(self) -> str:
        pass

    @abstractmethod
    def generate(self, context: Context) -> str:
        pass
