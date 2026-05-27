"""Tests for utility functions."""

from __future__ import annotations

from threatlens.utils.crypto import CryptoUtils


class TestCryptoUtils:
    def test_hash_signal(self):
        data = {"key": "value", "num": 42}
        h1 = CryptoUtils.hash_signal(data)
        h2 = CryptoUtils.hash_signal(data)
        assert h1 == h2
        assert isinstance(h1, str)

    def test_hash_different_inputs(self):
        h1 = CryptoUtils.hash_signal({"a": 1})
        h2 = CryptoUtils.hash_signal({"a": 2})
        assert h1 != h2

    def test_generate_api_key(self):
        key = CryptoUtils.generate_api_key()
        assert key.startswith("tl_")
        assert len(key) > 10

    def test_sign_and_verify(self):
        payload = "test-payload"
        secret = "my-secret-key"
        sig = CryptoUtils.sign_payload(payload, secret)
        assert CryptoUtils.verify_signature(payload, secret, sig) is True
        assert CryptoUtils.verify_signature(payload, "wrong-secret", sig) is False

    def test_anonymize_ip(self):
        assert CryptoUtils.anonymize_ip("192.168.1.100") == "192.168.1.0"
        assert CryptoUtils.anonymize_ip("10.0.0.5") == "10.0.0.0"

    def test_anonymize_invalid_ip(self):
        assert CryptoUtils.anonymize_ip("not-an-ip") == "not-an-ip"

    def test_anonymize_text_short(self):
        text = "short text"
        assert CryptoUtils.anonymize_text(text, max_len=100) == text

    def test_anonymize_text_long(self):
        text = "A" * 1000
        result = CryptoUtils.anonymize_text(text, max_len=100)
        assert len(result) == 103
        assert result.startswith("A" * 50)
        assert result.endswith("A" * 50)
        assert "..." in result
