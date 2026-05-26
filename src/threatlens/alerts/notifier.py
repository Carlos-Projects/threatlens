"""Alert notification — sends alerts via email, Telegram, and webhooks."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from threatlens.models import Alert

logger = logging.getLogger(__name__)


class AlertNotifier:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    async def send_telegram(self, alert: Alert, chat_id: str = "") -> bool:
        bot_token = self.config.get("telegram", {}).get("bot_token", "")
        chat = chat_id or self.config.get("telegram", {}).get("chat_id", "")
        if not bot_token or not chat:
            return False

        message = (
            f"\U0001f6a8 ThreatLens Alert [{alert.severity.value.upper()}]\n"
            f"{alert.title}\n\n"
            f"{alert.description[:500]}\n\n"
            f"Risk Score: {alert.risk_score}\n"
            f"TTPs: {', '.join(t.get('id', '') for t in alert.ttps[:5])}\n"
            f"Signals: {len(alert.signal_ids)}"
        )

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            try:
                response = await client.post(
                    f"https://api.telegram.org/bot{bot_token}/sendMessage",
                    json={"chat_id": chat, "text": message, "parse_mode": "HTML"},
                )
                return response.status_code == 200
            except Exception as e:
                logger.warning("Telegram notify error: %s", e)
                return False

    async def send_webhook(self, alert: Alert, url: str = "") -> bool:
        webhook_url = url or self.config.get("webhook", {}).get("url", "")
        if not webhook_url:
            return False

        payload = {
            "event": "alert",
            "severity": alert.severity.value,
            "title": alert.title,
            "description": alert.description[:1000],
            "risk_score": alert.risk_score,
            "ttps": alert.ttps,
            "signal_ids": alert.signal_ids,
            "timestamp": alert.timestamp,
            "source": "threatlens",
        }

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            try:
                response = await client.post(
                    webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                return response.status_code < 300
            except Exception as e:
                logger.warning("Webhook notify error: %s", e)
                return False

    async def notify(self, alert: Alert) -> dict[str, bool]:
        results: dict[str, bool] = {
            "telegram": False,
            "webhook": False,
        }

        if self.config.get("telegram", {}).get("enabled", True):
            results["telegram"] = await self.send_telegram(alert)

        if self.config.get("webhook", {}).get("enabled", True):
            results["webhook"] = await self.send_webhook(alert)

        return results
