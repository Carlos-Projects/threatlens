"""Base class for all source clients."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from threatlens.models import RawSignal


class SourceClient(ABC):
    name: str

    @abstractmethod
    async def fetch(self, **kwargs: Any) -> list[RawSignal]: ...
