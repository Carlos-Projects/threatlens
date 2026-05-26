"""Tests for alert notifier."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from threatlens.alerts.notifier import AlertNotifier
from threatlens.models import Alert, Severity


def _mock_async_client(post_return: MagicMock | None = None) -> AsyncMock:
    mock_client = AsyncMock()
    if post_return:
        mock_client.post.return_value = post_return
    mock_client.__aenter__.return_value = mock_client
    return mock_client


class TestAlertNotifier:
    def setup_method(self):
        self.notifier = AlertNotifier(
            {
                "telegram": {"bot_token": "test", "chat_id": "123", "enabled": True},
                "webhook": {"url": "http://example.com/webhook", "enabled": True},
            }
        )
        self.telegram_only = AlertNotifier(
            {
                "telegram": {"bot_token": "tg_test", "chat_id": "999", "enabled": True},
                "webhook": {"enabled": False},
            }
        )

    def _make_alert(self) -> Alert:
        return Alert(
            id="alert-test",
            title="Test Alert",
            description="Test description",
            severity=Severity.CRITICAL,
            correlation_ids=[],
            signal_ids=[],
            ttps=[],
            enriched={},
        )

    @pytest.mark.asyncio
    async def test_send_telegram_no_credentials(self):
        notifier = AlertNotifier({})
        result = await notifier.send_telegram(self._make_alert())
        assert result is False

    @pytest.mark.asyncio
    async def test_send_webhook_no_url(self):
        notifier = AlertNotifier({"webhook": {"url": ""}})
        result = await notifier.send_webhook(self._make_alert())
        assert result is False

    @pytest.mark.asyncio
    async def test_send_webhook_network_error(self):
        mock_client = _mock_async_client()
        mock_client.post.side_effect = Exception("Network error")

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await self.notifier.send_webhook(self._make_alert())
            assert result is False

    @pytest.mark.asyncio
    async def test_send_webhook_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        mock_client = _mock_async_client(post_return=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await self.notifier.send_webhook(self._make_alert())
            assert result is True

    @pytest.mark.asyncio
    async def test_notify_with_disabled_channels(self):
        notifier = AlertNotifier(
            {
                "telegram": {"enabled": False},
                "webhook": {"enabled": False},
            }
        )
        result = await notifier.notify(self._make_alert())
        assert result == {"telegram": False, "webhook": False}

    @pytest.mark.asyncio
    async def test_send_telegram_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = _mock_async_client(post_return=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await self.telegram_only.send_telegram(self._make_alert())
            assert result is True

    @pytest.mark.asyncio
    async def test_send_telegram_network_error(self):
        mock_client = _mock_async_client()
        mock_client.post.side_effect = Exception("Telegram API error")

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await self.telegram_only.send_telegram(self._make_alert())
            assert result is False

    @pytest.mark.asyncio
    async def test_send_telegram_missing_chat_id(self):
        notifier = AlertNotifier({"telegram": {"bot_token": "test", "chat_id": ""}})
        result = await notifier.send_telegram(self._make_alert())
        assert result is False

    @pytest.mark.asyncio
    async def test_send_webhook_non_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_client = _mock_async_client(post_return=mock_resp)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await self.notifier.send_webhook(self._make_alert())
            assert result is False

    @pytest.mark.asyncio
    async def test_notify_with_enabled_channels(self):
        mock_post = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp
        mock_client = _mock_async_client(post_return=mock_resp)
        mock_client.post = mock_post
        mock_client.__aenter__.return_value = mock_client

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await self.notifier.notify(self._make_alert())
            assert "telegram" in result
            assert "webhook" in result
