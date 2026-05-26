"""Cryptographic utilities for ThreatLens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any


class CryptoUtils:
    @staticmethod
    def hash_signal(data: dict[str, Any]) -> str:
        raw = str(sorted(data.items()))
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def generate_api_key() -> str:
        return f"tl_{secrets.token_urlsafe(32)}"

    @staticmethod
    def sign_payload(payload: str, secret: str) -> str:
        return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_signature(payload: str, secret: str, signature: str) -> bool:
        expected = CryptoUtils.sign_payload(payload, secret)
        return hmac.compare_digest(expected, signature)

    @staticmethod
    def anonymize_ip(ip: str) -> str:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0"
        return ip

    @staticmethod
    def anonymize_text(text: str, max_len: int = 500) -> str:
        if len(text) > max_len:
            half = max_len // 2
            return text[:half] + "..." + text[-half:]
        return text
