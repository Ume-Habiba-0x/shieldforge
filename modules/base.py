"""ShieldForge — Abstract base class for all scanners."""

from abc import ABC, abstractmethod
from typing import List
import time

from core.context import Context
from core.models import Finding, ScanResult


class BaseScanner(ABC):
    """Template for all ShieldForge scanner modules."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    def validate(self, context: Context) -> bool:
        if not context.config.target_url:
            return False
        return True

    @abstractmethod
    def scan(self, context: Context) -> ScanResult:
        pass

    def _create_result(self, findings: List[Finding],
                      errors: List[str] = None,
                      duration_ms: int = 0,
                      target: str = "") -> ScanResult:
        return ScanResult(
            module_name=self.name,
            findings=findings or [],
            errors=errors or [],
            duration_ms=duration_ms,
            target=target
        )

    def run(self, context: Context) -> ScanResult:
        if not self.validate(context):
            return self._create_result(errors=["Validation failed"])

        start = time.time()
        try:
            result = self.scan(context)
        except Exception as e:
            result = self._create_result(errors=[f"Scan failed: {str(e)}"])

        result.duration_ms = int((time.time() - start) * 1000)
        return result
