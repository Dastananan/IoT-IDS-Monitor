"""
=============================================================================
ФАЙЛ: core/ids_engine.py
МОДУЛЬ: IoT Кіру Анықтау Жүйесінің Ядросы (IDS Engine)
=============================================================================
ДИПЛОМДЫҚ ЖҰМЫС:
    Тақырып  : Смарт құрылғылар мен сенсорларды кибер шабуылдардан
                қорғау әдістерін зерттеу
    Орындаған: Сарбасов Д.
    Топ      : СИБ(ЗБИС)к-22-9Б
    Оқу орны : АУЭС, Алматы, 2026

МОДУЛЬДІҢ СИПАТТАМАСЫ:
    Бұл файл IoT IDS жүйесінің негізгі ядросын құрайды.
    6 мамандандырылған детектор, SQLite деректер базасы,
    және IoTIDS оркестратор класы орналасқан.

ДЕТЕКТОРЛАР:
    1. DoSDetector          — DoS/DDoS шабуылдарын анықтайды
    2. BruteForceDetector   — Пароль болжау шабуылдарын анықтайды
    3. MQTTAttackDetector   — MQTT протоколына шабуылдарды анықтайды
    4. MITMDetector         — ARP Spoofing / MITM шабуылдарды анықтайды
    5. PortScanDetector     — Порт сканерлеуді анықтайды
    6. ReplayAttackDetector — Replay шабуылдарды анықтайды

АЛГОРИТМДЕР:
    - Скользящее окно (Sliding Window) — DoS/DDoS, Port Scan үшін
    - Сәтсіздік счётчигі               — Brute-Force үшін
    - Топик инспекция                   — MQTT Injection үшін
    - ARP кесте мониторинг              — MITM/ARP Spoofing үшін
    - MD5 хэш салыстыру                 — Replay Attack үшін
=============================================================================
"""

# ── Стандартты Python кітапханалары ─────────────────────────────────────────
import time                                  # Уақытты өлшеу
import logging                               # Лог жазу
import os                                    # Файл жүйесі
import sqlite3                               # Деректер базасы
import threading                             # Параллель жұмыс
import hashlib                               # MD5/SHA256 хэш
import json                                  # JSON формат
from collections import defaultdict, deque  # Оңтайлы деректер құрылымдары
from dataclasses import dataclass, field    # Деректер класстары
from typing import Optional                  # Тип аннотациялар
from datetime import datetime                # Дата/уақыт

# ── Жаңа модульдер (v2) ──────────────────────────────────────────
try:
    from core.anomaly_detector  import AnomalyDetector
    from core.correlation_engine import CorrelationEngine
    ANOMALY_AVAILABLE     = True
    CORRELATION_AVAILABLE = True
except ImportError:
    try:
        from anomaly_detector  import AnomalyDetector
        from correlation_engine import CorrelationEngine
        ANOMALY_AVAILABLE     = True
        CORRELATION_AVAILABLE = True
    except ImportError:
        ANOMALY_AVAILABLE     = False
        CORRELATION_AVAILABLE = False


# ════════════════════════════════════════════════════════════════════════════
# ЛОГ ЖҮЙЕСІ
# Барлық оқиғалар: 1) logs/ids.log файлына  2) Консольге жазылады
# ════════════════════════════════════════════════════════════════════════════
os.makedirs("logs", exist_ok=True)

_fmt = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
_fh = logging.FileHandler("logs/ids.log", encoding="utf-8")
_fh.setFormatter(_fmt)
_ch = logging.StreamHandler()
_ch.setFormatter(_fmt)

logger = logging.getLogger("IoT_IDS")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    logger.addHandler(_fh)
    logger.addHandler(_ch)


# ════════════════════════════════════════════════════════════════════════════
# SQLITE ДЕРЕКТЕР БАЗАСЫ
# Барлық анықталған шабуылдар автоматты базаға жазылады.
# Thread-safe: бірнеше thread бір уақытта жаза алады.
#
# Кесте: alerts
#   id           — бірегей нөмір (автоматты)
#   attack_type  — шабуыл түрі (DoS/DDoS, Brute-Force ...)
#   severity     — маңыздылық (CRITICAL / HIGH / MEDIUM / LOW)
#   src_ip       — шабуылдаушы IP-адрес
#   description  — толық сипаттама
#   detector     — анықтаған детектор атауы
#   blocked      — IP блокталды ма (0/1)
#   created_at   — анықталған уақыты
# ════════════════════════════════════════════════════════════════════════════
class IDSDatabase:
    def __init__(self, db_path="logs/ids_alerts.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.Lock()
        self._init_tables()
        logger.info(f"Деректер базасы іске қосылды: {db_path}")

    def _conn(self):
        c = sqlite3.connect(self.db_path, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def _init_tables(self):
        # Кестелер мен индекстерді бір рет жасаймыз
        with self._conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    attack_type  TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    src_ip       TEXT NOT NULL,
                    description  TEXT NOT NULL,
                    detector     TEXT,
                    blocked      INTEGER DEFAULT 0,
                    packet_count INTEGER DEFAULT 0,
                    created_at   TEXT NOT NULL
                );
                -- Іздеу жылдамдығын арттыратын индекстер
                CREATE INDEX IF NOT EXISTS idx_type ON alerts(attack_type);
                CREATE INDEX IF NOT EXISTS idx_ip   ON alerts(src_ip);
                CREATE INDEX IF NOT EXISTS idx_time ON alerts(created_at);
            """)

    def save_alert(self, alert) -> int:
        # Алертті базаға жазу, жаңа жазбаның ID-ін қайтару
        with self._lock, self._conn() as c:
            cur = c.execute(
                """INSERT INTO alerts
                   (attack_type, severity, src_ip, description,
                    detector, blocked, packet_count, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    alert.attack_type, alert.severity,
                    alert.src_ip,      alert.description,
                    alert.detector,    1 if alert.blocked else 0,
                    alert.packet_count,
                    datetime.fromtimestamp(alert.timestamp).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                )
            )
            return cur.lastrowid

    def get_recent(self, limit=100) -> list:
        # Соңғы N алертті жаңадан ескіге қарай қайтару
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        # Базадан толық статистика
        with self._conn() as c:
            total   = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            blocked = c.execute(
                "SELECT COUNT(*) FROM alerts WHERE blocked=1"
            ).fetchone()[0]
            by_type = [dict(r) for r in c.execute(
                "SELECT attack_type, COUNT(*) cnt FROM alerts "
                "GROUP BY attack_type ORDER BY cnt DESC"
            )]
            by_sev  = [dict(r) for r in c.execute(
                "SELECT severity, COUNT(*) cnt FROM alerts GROUP BY severity"
            )]
            top_ips = [dict(r) for r in c.execute(
                "SELECT src_ip, COUNT(*) cnt FROM alerts "
                "GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"
            )]
            by_day  = [dict(r) for r in c.execute(
                "SELECT substr(created_at,1,10) day, COUNT(*) cnt "
                "FROM alerts GROUP BY day ORDER BY day DESC LIMIT 7"
            )]
            return {
                "total_alerts":   total,
                "blocked_alerts": blocked,
                "by_type":        by_type,
                "by_severity":    by_sev,
                "top_ips":        top_ips,
                "by_day":         by_day,
            }

    def clear(self):
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM alerts")
        logger.info("База тазартылды")


# ════════════════════════════════════════════════════════════════════════════
# ДЕРЕКТЕР КЛАССТАРЫ
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class NetworkPacket:
    """
    IoT желісіндегі желілік пакет моделі.

    src_ip       — бастапқы IP  (шабуылдаушы немесе заңды құрылғы)
    dst_ip       — мақсат IP    (MQTT брокер, шлюз)
    protocol     — протокол     (MQTT, TCP, UDP, ARP)
    payload_size — пакет өлшемі байтпен
    timestamp    — UNIX уақыт белгісі
    port         — мақсат порт  (1883=MQTT, 22=SSH, 23=Telnet ...)
    payload      — пакет мазмұны (мәтіндік)
    flags        — желілік туылар [SYN, ARP, TLS_CERT ...]
    """
    src_ip:       str
    dst_ip:       str
    protocol:     str
    payload_size: int
    timestamp:    float = field(default_factory=time.time)
    port:         int   = 0
    payload:      str   = ""
    flags:        list  = field(default_factory=list)


@dataclass
class Alert:
    """
    Анықталған шабуыл туралы алерт.

    Маңыздылық деңгейлері:
        CRITICAL — дереу іс-қимыл қажет (DoS, MQTT Injection, ARP Spoofing)
        HIGH     — жоғары қауіп (Brute-Force, Port Scan, TLS Spoofing)
        MEDIUM   — орташа қауіп (Replay Attack, MQTT Anomaly)
        LOW      — ақпараттық ескерту (бейтаныс құрылғы)
    """
    attack_type:  str
    severity:     str
    src_ip:       str
    description:  str
    timestamp:    float = field(default_factory=time.time)
    packet_count: int   = 0
    blocked:      bool  = False
    detector:     str   = ""
    db_id:        int   = 0    # SQLite базасындағы жазба нөмірі

    def to_dict(self) -> dict:
        return {
            "id":           self.db_id,
            "attack_type":  self.attack_type,
            "severity":     self.severity,
            "src_ip":       self.src_ip,
            "description":  self.description,
            "timestamp":    datetime.fromtimestamp(
                                self.timestamp
                            ).strftime("%H:%M:%S"),
            "packet_count": self.packet_count,
            "blocked":      self.blocked,
            "detector":     self.detector,
        }


# ════════════════════════════════════════════════════════════════════════════
# ДЕТЕКТОР 1: DoSDetector
# ════════════════════════════════════════════════════════════════════════════
class DoSDetector:
    """
    DoS/DDoS шабуылдарын Скользящее окно алгоритмімен анықтайды.

    Алгоритм принципі:
        5 секундтық уақыт терезесінде бір IP-дан 50-ден астам
        пакет келсе — DoS/DDoS шабуылы деп анықталады.

        deque (екі жақты кезек) пайдаланылады:
          - Жаңа пакет оң жақтан қосылады: append()
          - Ескі пакеттер сол жақтан алынады: popleft()
          - Уақытша күрделілік: O(1) — тізімдерге қарағанда жылдам

    Алерт деңгейлері:
        HIGH     — 50-100 пакет / 5 секунд
        CRITICAL — 100+ пакет / 5 секунд
    """

    def __init__(self, threshold: int = 50, window_sec: int = 5):
        self.threshold  = threshold    # Пакет саны шегі
        self.window_sec = window_sec   # Уақыт терезесі (секунд)
        # {IP-адрес: пакет уақыттарының кезегі}
        self.packet_times: dict[str, deque] = defaultdict(deque)

    def analyze(self, packet: NetworkPacket) -> Optional[Alert]:
        ip  = packet.src_ip
        now = packet.timestamp
        dq  = self.packet_times[ip]

        dq.append(now)                                     # Жаңа пакет қос
        while dq and dq[0] < now - self.window_sec:       # Ескілерін тазарт
            dq.popleft()

        count = len(dq)                                    # Терезедегі пакет
        if count >= self.threshold:
            return Alert(
                attack_type  = "DoS/DDoS",
                severity     = "CRITICAL" if count > self.threshold * 2 else "HIGH",
                src_ip       = ip,
                description  = (f"Пакет тасқыны: {count} пакет / "
                                f"{self.window_sec}с (шек: {self.threshold})"),
                packet_count = count,
                blocked      = True,
                detector     = "DoSDetector",
            )
        return None


# ════════════════════════════════════════════════════════════════════════════
# ДЕТЕКТОР 2: BruteForceDetector
# ════════════════════════════════════════════════════════════════════════════
class BruteForceDetector:
    """
    Пароль болжау (Brute-Force) шабуылдарын анықтайды.

    Бақыланатын порттар:
        22   — SSH (Secure Shell) — Linux серверлері
        23   — Telnet            — Ескі IoT құрылғылары
        80   — HTTP              — Веб-интерфейстер
        443  — HTTPS             — Шифрлы веб
        1883 — MQTT              — IoT хабар алмасу
        8883 — MQTT TLS          — Шифрлы MQTT

    Сәтсіздік белгілері (payload-та болса):
        "401"              → HTTP Unauthorized
        "403"              → HTTP Forbidden
        "auth_fail"        → Аутентификация сәтсіз
        "login_fail"       → Кіру сәтсіз
        "unauthorized"     → Рұқсат жоқ
        "invalid_password" → Қате пароль
    """

    AUTH_PORTS    = {22, 23, 80, 443, 1883, 8883}
    FAIL_KEYWORDS = [
        "401", "403", "auth_fail", "login_fail",
        "unauthorized", "invalid_password"
    ]

    def __init__(self, max_attempts: int = 5, window_sec: int = 30):
        self.max_attempts = max_attempts   # Максимум сәтсіз кіру саны
        self.window_sec   = window_sec     # Бақылау терезесі
        self.failed: dict[str, deque] = defaultdict(deque)

    def analyze(self, packet: NetworkPacket) -> Optional[Alert]:
        # Тек аутентификация порттарын тексеру
        if packet.port not in self.AUTH_PORTS:
            return None

        # Payload-та сәтсіздік белгісі бар ма?
        if not any(kw in packet.payload.lower() for kw in self.FAIL_KEYWORDS):
            return None

        ip, now = packet.src_ip, packet.timestamp
        dq = self.failed[ip]
        dq.append(now)
        while dq and dq[0] < now - self.window_sec:
            dq.popleft()

        count = len(dq)
        if count >= self.max_attempts:
            return Alert(
                attack_type  = "Brute-Force",
                severity     = "HIGH",
                src_ip       = ip,
                description  = (f"Пароль болжау: {count} сәтсіз кіру / "
                                f"{self.window_sec}с"),
                packet_count = count,
                blocked      = True,
                detector     = "BruteForceDetector",
            )
        return None


# ════════════════════════════════════════════════════════════════════════════
# ДЕТЕКТОР 3: MQTTAttackDetector
# ════════════════════════════════════════════════════════════════════════════
class MQTTAttackDetector:
    """
    MQTT протоколына бағытталған шабуылдарды анықтайды.

    MQTT — IoT-тің стандартты хабар алмасу протоколы.
    Publish-Subscribe архитектурасы:
        Датчик → [PUBLISH /sensors/temp] → Брокер → Клиент

    Тыйым салынған топиктер (жазу мүмкін емес):
        /admin    — администратор командалары
        /config   — жүйе конфигурациясы
        /firmware — микробағдарлама жаңарту
        /cmd      — жүйелік командалар
        /control  — басқару интерфейсі
        /$SYS     — MQTT брокердің жүйелік топигі
        /root     — тамыр каталог
        /system   — жүйелік параметрлер
    """

    SENSITIVE_TOPICS = [
        "/admin", "/config", "/firmware", "/cmd",
        "/control", "/$SYS", "/root", "/system"
    ]
    MAX_PAYLOAD_SIZE = 4096  # байт — осыдан астам payload аномальды

    def __init__(self):
        self.known_devices: set[str] = set()  # Белгілі IoT құрылғылары

    def analyze(self, packet: NetworkPacket) -> Optional[Alert]:
        if packet.protocol != "MQTT":
            return None   # MQTT емес пакеттерді өткіз

        ip, payload = packet.src_ip, packet.payload

        # 1. Тыйым салынған топикке жазу → CRITICAL (IP блокталады)
        for topic in self.SENSITIVE_TOPICS:
            if topic in payload:
                return Alert(
                    attack_type  = "MQTT Injection",
                    severity     = "CRITICAL",
                    src_ip       = ip,
                    description  = f"Тыйым салынған топикке жазу: {topic}",
                    packet_count = 1,
                    blocked      = True,
                    detector     = "MQTTAttackDetector",
                )

        # 2. Аномальды үлкен payload → MEDIUM
        #    (деректер ұрлау немесе буфер толтыру шабуылы болуы мүмкін)
        if packet.payload_size > self.MAX_PAYLOAD_SIZE:
            return Alert(
                attack_type  = "MQTT Anomaly",
                severity     = "MEDIUM",
                src_ip       = ip,
                description  = (f"Аномальды payload: {packet.payload_size} байт "
                                f"(макс: {self.MAX_PAYLOAD_SIZE})"),
                packet_count = 1,
                blocked      = False,
                detector     = "MQTTAttackDetector",
            )

        # 3. Бейтаныс құрылғы CONNECT жіберді → LOW
        if ip not in self.known_devices and "CONNECT" in payload:
            self.known_devices.add(ip)
            return Alert(
                attack_type  = "MQTT Unauthorized",
                severity     = "LOW",
                src_ip       = ip,
                description  = "Бейтаныс IoT құрылғысы брокерге қосылды",
                packet_count = 1,
                blocked      = False,
                detector     = "MQTTAttackDetector",
            )
        return None


# ════════════════════════════════════════════════════════════════════════════
# ДЕТЕКТОР 4: MITMDetector
# ════════════════════════════════════════════════════════════════════════════
class MITMDetector:
    """
    MITM (Man-in-the-Middle) / ARP Spoofing шабуылдарын анықтайды.

    ARP Spoofing принципі:
        Заңды жағдай:
            Датчик (192.168.1.10 / AA:BB:CC:DD:EE:FF)
                    ↓ заңды трафик
            Шлюз   (192.168.1.1)

        Шабуыл жағдайы:
            Датчик (192.168.1.10 / AA:BB:CC:DD:EE:FF)
                    ↓ трафик шабуылдаушыға бұрылды
            Шабуылдаушы (192.168.1.1 деп өзін таныстырды)
                    ↓
            Шлюз   (192.168.1.1)

    Анықтау:
        ip_mac_table сөздігінде IP→MAC байланысы сақталады.
        ARP пакеті алынғанда MAC өзгерсе — ARP Spoofing!
    """

    def __init__(self):
        self.ip_mac_table: dict[str, str] = {}  # IP → MAC кестесі
        self.cert_hashes:  dict[str, str] = {}  # IP → TLS сертификат хэші

    def analyze(self, packet: NetworkPacket) -> Optional[Alert]:
        ip, payload = packet.src_ip, packet.payload

        # ── ARP Spoofing анықтау ──────────────────────────────────────
        if "ARP" in packet.flags:
            # Payload форматы: "IP:MAC"  мысалы: "192.168.1.10:AA:BB:CC:DD:EE:FF"
            parts = payload.split(":", 1)
            if len(parts) == 2:
                claimed_ip  = parts[0]
                claimed_mac = parts[1]
                if claimed_ip in self.ip_mac_table:
                    if self.ip_mac_table[claimed_ip] != claimed_mac:
                        # MAC ауысты — ARP Spoofing!
                        return Alert(
                            attack_type  = "MITM / ARP Spoofing",
                            severity     = "CRITICAL",
                            src_ip       = ip,
                            description  = (
                                f"ARP жалғандық: {claimed_ip} → "
                                f"жаңа MAC {claimed_mac} "
                                f"(бұрын: {self.ip_mac_table[claimed_ip]})"
                            ),
                            packet_count = 1,
                            blocked      = True,
                            detector     = "MITMDetector",
                        )
                self.ip_mac_table[claimed_ip] = claimed_mac  # Кестеге жаз

        # ── TLS Сертификат ауысуын анықтау ───────────────────────────
        if "TLS_CERT" in packet.flags:
            cert_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
            if ip in self.cert_hashes and self.cert_hashes[ip] != cert_hash:
                return Alert(
                    attack_type  = "MITM / Cert Spoofing",
                    severity     = "HIGH",
                    src_ip       = ip,
                    description  = "TLS сертификат ауысты — SSL-strip немесе MITM",
                    packet_count = 1,
                    blocked      = False,
                    detector     = "MITMDetector",
                )
            self.cert_hashes[ip] = cert_hash
        return None


# ════════════════════════════════════════════════════════════════════════════
# ДЕТЕКТОР 5: PortScanDetector
# ════════════════════════════════════════════════════════════════════════════
class PortScanDetector:
    """
    Порт сканерлеуді анықтайды (Nmap, Masscan, т.б.).

    Принципі:
        Шабуылдаушы желідегі ашық порттарды анықтау үшін
        бірнеше портқа SYN пакет жіберіп тексереді.

    Анықтау:
        10 секунд ішінде бір IP-дан 15+ бірегей портқа
        сұрау болса — порт сканері деп анықталады.
    """

    def __init__(self, port_threshold: int = 15, window_sec: int = 10):
        self.port_threshold = port_threshold
        self.window_sec     = window_sec
        # IP → (уақыт, порт) жұптарының кезегі
        self.port_history: dict[str, deque] = defaultdict(deque)

    def analyze(self, packet: NetworkPacket) -> Optional[Alert]:
        if packet.port == 0:
            return None

        ip, now = packet.src_ip, packet.timestamp
        dq = self.port_history[ip]
        dq.append((now, packet.port))

        while dq and dq[0][0] < now - self.window_sec:
            dq.popleft()

        # Терезедегі бірегей порттар санауы
        unique_ports = len({port for _, port in dq})
        if unique_ports >= self.port_threshold:
            return Alert(
                attack_type  = "Port Scan",
                severity     = "HIGH",
                src_ip       = ip,
                description  = (f"Порт сканерлеу: {unique_ports} бірегей порт "
                                f"/ {self.window_sec}с"),
                packet_count = len(dq),
                blocked      = True,
                detector     = "PortScanDetector",
            )
        return None


# ════════════════════════════════════════════════════════════════════════════
# ДЕТЕКТОР 6: ReplayAttackDetector
# ════════════════════════════════════════════════════════════════════════════
class ReplayAttackDetector:
    """
    Replay (Қайталау) шабуылдарын анықтайды.

    Принципі:
        Шабуылдаушы заңды аутентификация пакетін «ұстап»,
        кейін сол пакетті қайта жіберіп, кіруге тырысады.

        Мысал:
            Заңды: Датчик → [TOKEN=abc123] → Брокер ✓
            Шабуыл: Шабуылдаушы → [TOKEN=abc123] → Брокер ← қайталау!

    Анықтау: MD5 хэш салыстыру
        Payload-тың MD5 хэші есептеліп сақталады.
        60 секунд ішінде бірдей хэш 3+ рет қайталанса — шабуыл!
    """

    def __init__(self, repeat_threshold: int = 3, window_sec: int = 60):
        self.repeat_threshold = repeat_threshold
        self.window_sec       = window_sec
        # IP → {payload_hash → уақыттар кезегі}
        self.seen: dict = defaultdict(lambda: defaultdict(deque))

    def analyze(self, packet: NetworkPacket) -> Optional[Alert]:
        if not packet.payload or len(packet.payload) < 8:
            return None   # Тым қысқа payload — анықтауға жарамайды

        ip, now = packet.src_ip, packet.timestamp
        # Payload-тың MD5 хэші (алғашқы 12 символ жеткілікті)
        phash = hashlib.md5(packet.payload.encode()).hexdigest()[:12]
        dq    = self.seen[ip][phash]
        dq.append(now)

        while dq and dq[0] < now - self.window_sec:
            dq.popleft()

        count = len(dq)
        if count >= self.repeat_threshold:
            return Alert(
                attack_type  = "Replay Attack",
                severity     = "MEDIUM",
                src_ip       = ip,
                description  = (f"Пакет қайталауы: {count}× / "
                                f"{self.window_sec}с (хэш: {phash})"),
                packet_count = count,
                blocked      = False,
                detector     = "ReplayAttackDetector",
            )
        return None


# ════════════════════════════════════════════════════════════════════════════
# IoTIDS — БАСТЫ ОРКЕСТРАТОР КЛАСЫ
#
# Жұмыс принципі:
#   NetworkPacket → process_packet()
#       ├── blocked_ips тексеру
#       ├── 6 детектордан ПАРАЛЛЕЛЬ өткізу (break жоқ!)
#       ├── Алерттерді SQLite базасына жазу
#       ├── Лог файлына жазу
#       └── Callback функциялар шақыру (мысалы, Telegram)
# ════════════════════════════════════════════════════════════════════════════
class IoTIDS:
    """
    IoT IDS жүйесінің негізгі оркестратор класы.

    Маңызды ерекшелік:
        Барлық 6 детектор ПАРАЛЛЕЛЬ тексеріледі (break жоқ).
        Демек, бір пакет бірнеше шабуыл белгісін тудыруы мүмкін.
        Бұл жүйенің анықтау дәлдігін арттырады.
    """

    def __init__(self):
        # Деректер базасы (SQLite)
        self.db = IDSDatabase("logs/ids_alerts.db")

        # 6 детектор — барлығы параллель жұмыс жасайды
        self.detectors = [
            DoSDetector(threshold=50,          window_sec=5),
            BruteForceDetector(max_attempts=5, window_sec=30),
            MQTTAttackDetector(),
            MITMDetector(),
            PortScanDetector(port_threshold=15, window_sec=10),
            ReplayAttackDetector(repeat_threshold=3, window_sec=60),
        ]

        # Жүйе күйі
        self.alerts:        list  = []            # Барлық алерттер
        self.blocked_ips:   set   = set()         # Блокталған IP-лар
        self.total_packets: int   = 0             # Өңделген пакет саны
        self.stats:         dict  = defaultdict(int)  # Шабуыл статистикасы
        self.callbacks:     list  = []            # Алерт callback тізімі

        # ── v2: Жаңа модульдер ───────────────────────────────────
        if ANOMALY_AVAILABLE:
            self.anomaly_detector = AnomalyDetector()
        else:
            self.anomaly_detector = None

        if CORRELATION_AVAILABLE:
            self.correlation_engine = CorrelationEngine()
        else:
            self.correlation_engine = None

        self.correlated_alerts: list = []
        self.anomaly_alerts:    list = []

    def register_callback(self, fn):
        """
        Алерт анықталғанда шақырылатын функцияны тіркеу.
        Мысалы: Telegram хабар жіберу функциясы.

        Қолдану:
            ids.register_callback(telegram_bot.send_alert)
        """
        self.callbacks.append(fn)

    def process_packet(self, packet: NetworkPacket) -> list:
        """
        Пакетті барлық детекторлардан өткізіп, шабуылдарды анықтайды.

        Параметр : packet — талданатын NetworkPacket
        Қайтарады: list[Alert] — анықталған шабуылдар (бос болуы мүмкін)
        """
        self.total_packets += 1

        # Блокталған IP-дан пакет — дереу қайтар
        if packet.src_ip in self.blocked_ips:
            return []

        found_alerts = []

        # ── БАРЛЫҚ ДЕТЕКТОРДАН ПАРАЛЛЕЛЬ ӨТКІЗУ ──────────────────────
        for detector in self.detectors:
            try:
                result = detector.analyze(packet)
                if result:
                    found_alerts.append(result)
            except Exception as exc:
                logger.error(f"Детектор қатесі [{type(detector).__name__}]: {exc}")

        # ── АНЫҚТАЛҒАН АЛЕРТТЕРДІ ӨҢДЕУ ──────────────────────────────
        for alert in found_alerts:
            # 1. SQLite базасына жаз
            try:
                alert.db_id = self.db.save_alert(alert)
            except Exception as e:
                logger.error(f"БД жазу қатесі: {e}")

            # 2. Жады тізіміне қос
            self.alerts.append(alert)
            self.stats[alert.attack_type] += 1

            # 3. IP блоктау (қажет болса)
            if alert.blocked:
                self.blocked_ips.add(alert.src_ip)
                logger.warning(
                    f"[БЛОКТАЛДЫ] {alert.src_ip} | "
                    f"{alert.attack_type} | {alert.description}"
                )
            else:
                logger.info(
                    f"[АЛЕРТ] {alert.src_ip} | "
                    f"{alert.attack_type} | {alert.description}"
                )

            # 4. Тіркелген callback функцияларды шақыру
            #    (мысалы, Telegram хабар жіберу)
            for callback_fn in self.callbacks:
                try:
                    callback_fn(alert)
                except Exception:
                    pass

        # ── v2: Аномалия детекциясы ──────────────────────────────
        if self.anomaly_detector and packet.payload_size is not None:
            anomaly = self.anomaly_detector.analyze(
                src_ip=packet.src_ip,
                dst_port=getattr(packet,"dst_port",None) or getattr(packet,"port",0) or 0,
                payload_size=packet.payload_size,
            )
            if anomaly:
                self.anomaly_alerts.append(anomaly)
                self.stats["Anomaly"] += 1
                for cb in self.callbacks:
                    try: cb(anomaly)
                    except: pass

        # ── v2: Корреляция движкі ─────────────────────────────────
        if self.correlation_engine:
            for alert in found_alerts:
                corr = self.correlation_engine.feed(alert.to_dict())
                if corr:
                    self.correlated_alerts.append(corr)
                    self.stats["APT"] += 1
                    for cb in self.callbacks:
                        try: cb(corr)
                        except: pass

        return found_alerts

    def get_summary(self) -> dict:
        """Жүйенің ағымдағы күйі (Flask API үшін)"""
        return {
            "total_packets": self.total_packets,
            "total_alerts":  len(self.alerts),
            "blocked_ips":   len(self.blocked_ips),
            "attack_stats":  dict(self.stats),
            "recent_alerts": [a.to_dict() for a in self.alerts[-30:]],
            "anomaly_alerts":    [a.to_dict() for a in self.anomaly_alerts[-10:]],
            "correlated_alerts": [a.to_dict() for a in self.correlated_alerts[-10:]],
            "anomaly_count":     len(self.anomaly_alerts),
            "corr_count":        len(self.correlated_alerts),
        }

    def get_db_stats(self) -> dict:
        """SQLite базасынан статистика"""
        return self.db.get_stats()

    def get_db_history(self, limit: int = 100) -> list:
        """SQLite базасынан соңғы N алерт"""
        return self.db.get_recent(limit)

    def reset_block(self, ip: str):
        """IP-ды блоктан шығару"""
        self.blocked_ips.discard(ip)
        logger.info(f"IP {ip} блоктан шығарылды")

    def export_report(self, path: str = "logs/report.json") -> dict:
        """Толық есепті JSON файлына сақтау"""
        os.makedirs(
            os.path.dirname(path) if os.path.dirname(path) else ".",
            exist_ok=True
        )
        report = {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary":      self.get_summary(),
            "db_stats":     self.get_db_stats(),
            "blocked_ips":  list(self.blocked_ips),
            "all_alerts":   [a.to_dict() for a in self.alerts],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        logger.info(f"JSON есеп сақталды: {path}")
        return report
