"""
Telegram бот хабарламасы — шабуыл анықталса дереу хабар жібереді
Баптау: config.py файлында BOT_TOKEN және CHAT_ID толтыр
"""

import threading
import time
import requests
from datetime import datetime

# ─── Баптау ───────────────────────────────────────────
# https://t.me/BotFather арқылы бот жасап TOKEN алыңыз
# https://t.me/userinfobot арқылы өзіңіздің CHAT_ID алыңыз
BOT_TOKEN = ""   # Мысал: "7412345678:AAHxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
CHAT_ID   = ""   # Мысал: "123456789"
# ──────────────────────────────────────────────────────

ENABLED = bool(BOT_TOKEN and CHAT_ID)

# Хабар жіберу жылдамдығын шектеу (spam болмасын)
_last_sent: dict[str, float] = {}
COOLDOWN_SEC = 30   # бір шабуыл типі үшін 30 сек-та бір рет


SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}


def _send(text: str):
    """Telegram API арқылы хабар жіберу"""
    if not ENABLED:
        return
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        requests.post(url, json={
            "chat_id":    CHAT_ID,
            "text":       text,
            "parse_mode": "HTML",
        }, timeout=5)
    except Exception as e:
        print(f"[Telegram] Қате: {e}")


def send_alert(alert) -> None:
    """
    Шабуыл туралы Telegram хабары.
    Cooldown: бір шабуыл типі 30 сек ішінде бір рет ғана жіберіледі.
    """
    if not ENABLED:
        return

    key = f"{alert.attack_type}:{alert.src_ip}"
    now = time.time()
    if now - _last_sent.get(key, 0) < COOLDOWN_SEC:
        return
    _last_sent[key] = now

    emoji = SEVERITY_EMOJI.get(alert.severity, "⚠️")
    blocked_text = "🔒 <b>IP БЛОКТАЛДЫ</b>" if alert.blocked else "👁 Бақылауда"
    time_str = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")

    text = (
        f"{emoji} <b>IoT IDS АЛЕРТ</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🎯 <b>Шабуыл:</b> {alert.attack_type}\n"
        f"⚡ <b>Деңгей:</b> {alert.severity}\n"
        f"🌐 <b>IP:</b> <code>{alert.src_ip}</code>\n"
        f"🔍 <b>Детектор:</b> {alert.detector}\n"
        f"📝 <b>Сипаттама:</b> {alert.description}\n"
        f"⏰ <b>Уақыт:</b> {time_str}\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"{blocked_text}"
    )

    # Бөлек thread-та жіберу (негізгі жұмысты тоқтатпасын)
    threading.Thread(target=_send, args=(text,), daemon=True).start()


def send_startup():
    """Сервер іске қосылғанда хабар"""
    _send(
        "✅ <b>IoT IDS Monitor іске қосылды</b>\n"
        f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "🛡 Жүйе мониторинг режимінде"
    )


def send_summary(ids_summary: dict):
    """Күнделікті қорытынды хабар"""
    stats = ids_summary.get("attack_stats", {})
    stats_text = "\n".join([f"  • {k}: {v}" for k, v in stats.items()]) or "  Шабуыл жоқ"
    _send(
        f"📊 <b>IoT IDS Қорытынды</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"📦 Өңделген пакет: {ids_summary.get('total_packets', 0)}\n"
        f"⚠️ Алерттер: {ids_summary.get('total_alerts', 0)}\n"
        f"🔒 Блокталған IP: {ids_summary.get('blocked_ips', 0)}\n"
        f"📋 Шабуылдар:\n{stats_text}"
    )


def test_connection() -> bool:
    """Telegram байланысын тексеру"""
    if not ENABLED:
        return False
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/getMe"
        r = requests.get(url, timeout=5)
        return r.status_code == 200
    except Exception:
        return False
