"""
CorrelationEngine — Корреляция детекторлары
============================================
Идея: Бір IP-дан бірнеше детектор іске қосылса →
      бұл үйлестірілген APT шабуылы.

Комиссияға аргумент:
    «Enterprise SIEM-нің негізгі қызметі — оқшауланған
     алерттерді байланыстырып, кешенді шабуылды анықтау.
     Splunk ES, IBM QRadar, Microsoft Sentinel — барлығы
     осылай жұмыс жасайды».

Мысалдар:
  PortScan → BruteForce          = Reconnaissance + Initial Access
  BruteForce → DoS               = Distraction DDoS
  PortScan → MQTT + BruteForce   = Full IoT compromise attempt
  Replay → MITM                  = Session hijack pattern
"""

import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ─── Паттерн матрицасы ───────────────────────────────────────────
# frozenset(attack_types) → (severity, campaign_name, description_kk)
ATTACK_PATTERNS = {
    frozenset(["Port Scan", "Brute-Force"]): (
        "CRITICAL",
        "Reconnaissance + Initial Access",
        "Порт сканерлеу → пароль болжау: нысан анықталып, рұқсатсыз кіру талпынысы",
    ),
    frozenset(["Port Scan", "MQTT Injection"]): (
        "CRITICAL",
        "IoT Compromise Attempt",
        "Порт сканерлеу → MQTT инъекция: IoT инфрақұрылымына кешенді шабуыл",
    ),
    frozenset(["Brute-Force", "DoS/DDoS"]): (
        "CRITICAL",
        "Distraction DDoS",
        "Brute-force + DoS: қорғанысты алаңдату арқылы рұқсатсыз кіру",
    ),
    frozenset(["Replay Attack", "MITM / ARP Spoofing"]): (
        "CRITICAL",
        "Session Hijack Pattern",
        "Replay + MITM: сессия ұрлау — трафик ұстап, пакет қайталау",
    ),
    frozenset(["Port Scan", "Brute-Force", "MQTT Injection"]): (
        "CRITICAL",
        "Full IoT Takeover",
        "Толық IoT шабуылы: барлау → кіру → MQTT бақылауды өзіне алу",
    ),
    frozenset(["DoS/DDoS", "MITM / ARP Spoofing"]): (
        "HIGH",
        "Network Disruption",
        "DoS + MITM: желіні бұзу + трафикті бағыттау",
    ),
    frozenset(["MITM / ARP Spoofing", "MQTT Injection"]): (
        "HIGH",
        "IoT Data Manipulation",
        "MITM + MQTT: IoT деректерін ұстап, өзгерту",
    ),
    frozenset(["Brute-Force", "Replay Attack"]): (
        "HIGH",
        "Credential Replay Attack",
        "Brute-force + Replay: тіркелгі деректерін ұрлап, қайта қолдану",
    ),
}

# Қанша секунд ішіндегі алерттер корреляцияланады
CORRELATION_WINDOW = 120   # 2 минут
# Минимум детектор саны корреляция үшін
MIN_DETECTORS      = 2
# Cool-down (бір IP үшін)
COOL_DOWN          = 60


@dataclass
class CorrelatedAlert:
    src_ip:       str
    campaign:     str           # шабуыл атауы
    severity:     str
    detectors:    list          # іске қосылған детектор тізімі
    alert_count:  int
    description:  str
    time_span:    float         # бірінші–соңғы алерт арасы (секунд)
    timestamp:    float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "src_ip":      self.src_ip,
            "campaign":    self.campaign,
            "severity":    self.severity,
            "detectors":   self.detectors,
            "alert_count": self.alert_count,
            "description": self.description,
            "time_span":   round(self.time_span, 1),
            "timestamp":   self.timestamp,
            "attack_type": f"APT: {self.campaign}",
            "detector":    "CorrelationEngine",
        }


class CorrelationEngine:
    """
    Алерттерді IP бойынша жинақтап, паттерн матрицасымен салыстырады.
    Сәйкестік табылса — CorrelatedAlert жасайды.
    """

    def __init__(
        self,
        window:      int = CORRELATION_WINDOW,
        min_detectors: int = MIN_DETECTORS,
        cool_down:   int = COOL_DOWN,
    ):
        self.window        = window
        self.min_detectors = min_detectors
        self.cool_down     = cool_down

        # ip → deque[(timestamp, attack_type, detector)]
        self._events: defaultdict = defaultdict(deque)

        # Корреляция тарихы
        self.correlated_alerts: list = []

        # Cool-down
        self._last_corr: dict = {}   # ip → timestamp

        # Статистика
        self.total_fed        = 0
        self.total_correlated = 0

        logger.info("CorrelationEngine инициализирован")

    # ─── Публичный API ───────────────────────────────────────────

    def feed(self, alert_dict: dict) -> Optional[CorrelatedAlert]:
        """
        Кез-келген детектор алертін беру.
        Егер бұл алерт корреляция паттернін аяқтаса →
        CorrelatedAlert қайтарады.

        Шақыру:
            corr = engine.feed(alert.to_dict())
        """
        self.total_fed += 1
        now = time.time()
        ip  = alert_dict.get("src_ip", "")
        atype = alert_dict.get("attack_type", "")
        det   = alert_dict.get("detector", "")

        if not ip or not atype:
            return None

        # Терезеден ескі оқиғаларды шығару
        self._evict(ip, now)

        # Жаңа оқиғаны қос
        self._events[ip].append((now, atype, det))

        # Корреляция тексеру
        return self._check_correlation(ip, now)

    def get_stats(self) -> dict:
        return {
            "total_fed":        self.total_fed,
            "total_correlated": self.total_correlated,
            "tracked_ips":      len(self._events),
            "recent":           [a.to_dict() for a in self.correlated_alerts[-10:]],
        }

    # ─── Ішкі логика ─────────────────────────────────────────────

    def _evict(self, ip: str, now: float):
        cutoff = now - self.window
        win = self._events[ip]
        while win and win[0][0] < cutoff:
            win.popleft()

    def _check_correlation(self, ip: str, now: float) -> Optional[CorrelatedAlert]:
        events = list(self._events[ip])
        if len(events) < self.min_detectors:
            return None

        # Cool-down
        if now - self._last_corr.get(ip, 0) < self.cool_down:
            return None

        # Бірегей шабуыл типтері
        unique_types = set(e[1] for e in events)
        if len(unique_types) < self.min_detectors:
            return None

        # 1. Паттерн матрицасында іздеу (ең нақты — ең ұзын жиын)
        best_match = None
        best_len   = 0
        for pattern, (sev, campaign, desc) in ATTACK_PATTERNS.items():
            if pattern.issubset(unique_types) and len(pattern) > best_len:
                best_match = (pattern, sev, campaign, desc)
                best_len   = len(pattern)

        if best_match:
            pattern, severity, campaign, description = best_match
        elif len(unique_types) >= 3:
            # 3+ бірегей детектор → Unknown APT
            severity    = "HIGH"
            campaign    = "Multi-Vector Attack"
            description = (
                f"{len(unique_types)} детектор іске қосылды: "
                + ", ".join(sorted(unique_types))
            )
        else:
            return None

        # Уақыт аралығы
        timestamps = [e[0] for e in events]
        time_span  = max(timestamps) - min(timestamps)

        alert = CorrelatedAlert(
            src_ip=ip,
            campaign=campaign,
            severity=severity,
            detectors=sorted(unique_types),
            alert_count=len(events),
            description=description,
            time_span=time_span,
        )

        self._last_corr[ip] = now
        self.correlated_alerts.append(alert)
        self.total_correlated += 1

        logger.warning(
            f"[КОРРЕЛЯЦИЯ] {ip} | {campaign} | "
            f"{len(unique_types)} детектор | Z={time_span:.0f}с ішінде"
        )
        return alert
