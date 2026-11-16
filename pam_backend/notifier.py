import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pam_backend.config import Config

class AlertNotifier:
    """
    Real-time Push Notification Dispatcher for ZeroVault PAM.
    Dispatches instant alerts directly to administrators' mobile devices
    via Telegram Bot API and generic Webhooks (Slack/Discord) when:
    - High-risk command is blocked in mid-air (e.g. cat /etc/shadow, rm -rf /).
    - Database query firewall detects an unauthorized SQL drop.
    - Merkle hash-chain detects cryptographic log tampering.
    - Ephemeral JIT lease expires or is forcibly revoked.
    """

    @classmethod
    def dispatch_security_alert(cls, alert_type: str, user: str, target: str,
                                details: str, severity: str = "CRITICAL") -> Dict[str, Any]:
        """
        Dispatches instant push alert to configured Telegram bot and webhook.
        Causes the admin's phone to vibrate/buzz instantly with sound.
        """
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Telegram Markdown formatted message
        icon = "🚨" if severity == "CRITICAL" else "⚠️"
        telegram_text = (
            f"{icon} *ZEROVAULT PAM: {severity} ALERT*\n\n"
            f"👤 *Identity:* `{user}`\n"
            f"🎯 *Target Server:* `{target}`\n"
            f"⚡ *Incident:* *{alert_type}*\n"
            f"🔍 *Details:* `{details}`\n"
            f"⏱️ *Timestamp:* _{now_str}_\n"
            f"🛡️ *Action:* *BLOCKED IN MID-AIR BY ZERO-TRUST PROXY*"
        )

        results = {
            "telegram": {"sent": False, "status": "NOT_CONFIGURED"},
            "webhook": {"sent": False, "status": "NOT_CONFIGURED"}
        }

        # 1. Dispatch to Telegram (Phone Buzz / Push Notification)
        bot_token = Config.TELEGRAM_BOT_TOKEN
        chat_id = Config.TELEGRAM_CHAT_ID

        if bot_token and chat_id and bot_token != "YOUR_TELEGRAM_BOT_TOKEN_HERE":
            try:
                url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                payload = json.dumps({
                    "chat_id": chat_id,
                    "text": telegram_text,
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": True
                }).encode("utf-8")

                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "ZeroVault-PAM-Security-Bot/1.0"
                    },
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    if resp.status == 200:
                        results["telegram"] = {"sent": True, "status": "DELIVERED_TO_PHONE"}
            except Exception as exc:
                results["telegram"] = {"sent": False, "status": f"ERROR: {str(exc)}"}
        else:
            # Standby mode when token is not yet entered
            results["telegram"] = {"sent": False, "status": "STANDBY (Add Telegram Bot Token to buzz phone)"}

        # 2. Dispatch to Generic Webhook (Discord / Slack) if configured
        webhook_url = Config.WEBHOOK_ALERT_URL
        if webhook_url:
            try:
                alert_text = f"{icon} **ZEROVAULT PAM ALERT**: {alert_type} on {target} by {user} - {details}"
                wh_payload = json.dumps({
                    "content": alert_text,
                    "text": alert_text,
                    "username": "ZeroVault PAM Security Bot"
                }).encode("utf-8")
                req = urllib.request.Request(
                    webhook_url,
                    data=wh_payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "ZeroVault-PAM-Security-Bot/1.0"
                    },
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    results["webhook"] = {"sent": True, "status": "DELIVERED"}
            except Exception as exc:
                results["webhook"] = {"sent": False, "status": f"ERROR: {str(exc)}"}

        return results

    @classmethod
    def send_test_ping(cls, bot_token: str = None, chat_id: str = None, webhook_url: str = None) -> Dict[str, Any]:
        """Sends an immediate verification ping to the user's phone via Telegram or Webhook."""
        token = bot_token or Config.TELEGRAM_BOT_TOKEN
        cid = chat_id or Config.TELEGRAM_CHAT_ID
        wh_url = webhook_url if webhook_url is not None else Config.WEBHOOK_ALERT_URL

        has_telegram = bool(token and cid and token != "YOUR_TELEGRAM_BOT_TOKEN_HERE" and cid != "YOUR_TELEGRAM_CHAT_ID_HERE")
        has_webhook = bool(wh_url and wh_url.strip())

        if not has_telegram and not has_webhook:
            return {
                "success": False,
                "message": "Neither Telegram credentials nor Webhook URL are configured. Provide Telegram Bot Token & Chat ID or a Discord/Slack Webhook URL."
            }

        outcomes = []
        overall_success = False

        # Test Telegram if configured
        if has_telegram:
            text = (
                "🔔 *ZEROVAULT PAM - TEST PHONE PING*\n\n"
                "Your phone is successfully connected to the ZeroVault Security Gateway!\n"
                "Whenever an attack or blocked command occurs, you will receive an instant buzz alert here."
            )
            try:
                url = f"https://api.telegram.org/bot{token}/sendMessage"
                payload = json.dumps({
                    "chat_id": cid,
                    "text": text,
                    "parse_mode": "Markdown"
                }).encode("utf-8")

                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "ZeroVault-PAM-Security-Bot/1.0"
                    },
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    if resp.status == 200:
                        overall_success = True
                        outcomes.append("Telegram ping delivered to phone")
                    else:
                        outcomes.append(f"Telegram status {resp.status}")
            except Exception as exc:
                outcomes.append(f"Telegram error: {str(exc)}")

        # Test Webhook if configured
        if has_webhook:
            try:
                wh_text = "🔔 **ZEROVAULT PAM - TEST PHONE PING**: Webhook integration verified! Instant attack alerts are active."
                wh_payload = json.dumps({
                    "content": wh_text,
                    "text": wh_text,
                    "username": "ZeroVault PAM Security Bot"
                }).encode("utf-8")
                req = urllib.request.Request(
                    wh_url,
                    data=wh_payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "ZeroVault-PAM-Security-Bot/1.0"
                    },
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    if resp.status in (200, 204):
                        overall_success = True
                        outcomes.append("Webhook alert delivered")
                    else:
                        outcomes.append(f"Webhook status {resp.status}")
            except Exception as exc:
                outcomes.append(f"Webhook error: {str(exc)}")

        return {
            "success": overall_success,
            "message": " | ".join(outcomes)
        }
