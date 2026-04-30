"""
AnomalyDetector — Статистикалық аномалия анықтау
=================================================
Алгоритм : Z-score + скользящий baseline
Идея     : Жүйе алдымен «қалыпты» трафикті үйренеді (baseline),
           содан кейін одан ауытқуды Z-score арқылы анықтайды.

Комиссияға аргумент:
    «Machine Learning-сіз статистикалық детекция —
     интерпретациялануы оңай, ресурс аз, нақты уақыт».
"""

import math
import time
import logging
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ─── Конфигурация ────────────────────────────────────────────────
WINDOW_SECONDS   = 60      # скользящее окно для baseline
MIN_SAMPLES      = 30      # минимум сэмплов до начала детекции
Z_THRESHOLD      = 3.0     # порог Z-score (3σ = 99.7% нормального распределения)
BURST_MULTIPLIER = 5.0     # мгновенный всплеск: в N раз выше среднего
COOL_DOWN        = 30      # секунд между повторными алертами с одного IP


@dataclass
class AnomalyAlert:
    src_ip:      str
    metric:      str          # «packets_per_sec», «unique_ports», «payload_size»
    observed:    float
    expected:    float
    z_score:     float
    severity:    str
    description: str
    timestamp:   float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "src_ip":      self.src_ip,
            "metric":      self.metric,
            "observed":    round(self.observed, 2),
            "expected":    round(self.expected, 2),
            "z_score":     round(self.z_score, 2),
            "severity":    self.severity,
            "description": self.description,
            "timestamp":   self.timestamp,
            "attack_type": "Anomaly",
            "detector":    "AnomalyDetector",
        }


class RollingStats:
    """
    Скользящее окно для вычисления среднего и стандартного отклонения.
    Алгоритм Уэлфорда — O(1) по памяти и времени.
    """

    def __init__(self, window: int = WINDOW_SECONDS):
        self.window  = window
        self._data: deque = deque()   # (timestamp, value)
        self._sum   = 0.0
        self._sum2  = 0.0            # сумма квадратов
        self._count = 0

    def add(self, value: float):
        now = time.time()
        self._data.append((now, value))
        self._sum  += value
        self._sum2 += value * value
        self._count += 1
        self._evict(now)

    def _evict(self, now: float):
        cutoff = now - self.window
        while self._data and self._data[0][0] < cutoff:
            _, v = self._data.popleft()
            self._sum   -= v
            self._sum2  -= v * v
            self._count -= 1

    def mean(self) -> float:
        return self._sum / self._count if self._count else 0.0

    def std(self) -> float:
        if self._count < 2:
            return 0.0
        variance = (self._sum2 - self._sum ** 2 / self._count) / (self._count - 1)
        return math.sqrt(max(variance, 0.0))

    def z_score(self, value: float) -> float:
        s = self.std()
        if s < 1e-9:
            return 0.0
        return (value - self.mean()) / s

    @property
    def count(self) -> int:
        return self._count


class AnomalyDetector:
    """
    Анализирует три метрики для каждого IP:
      1. packets_per_sec  — частота пакетов (DoS-pattern без порогового детектора)
      2. unique_ports      — количество уникальных портов (скрытый portscan)
      3. payload_size      — средний размер пейлоада (data exfiltration)

    Плюс глобальная метрика:
      4. global_pps        — общая нагрузка на сеть
    """

    def __init__(
        self,
        z_threshold:     float = Z_THRESHOLD,
        burst_multiplier: float = BURST_MULTIPLIER,
        min_samples:     int   = MIN_SAMPLES,
        cool_down:       int   = COOL_DOWN,
    ):
        self.z_threshold      = z_threshold
        self.burst_multiplier = burst_multiplier
        self.min_samples      = min_samples
        self.cool_down        = cool_down

        # Per-IP статистика
        self._pps:      defaultdict = defaultdict(lambda: RollingStats(60))
        self._ports:    defaultdict = defaultdict(lambda: RollingStats(60))
        self._payload:  defaultdict = defaultdict(lambda: RollingStats(60))

        # Окно для подсчёта пакетов в секунду (per IP)
        self._pkt_window: defaultdict = defaultdict(deque)

        # Глобальная PPS
        self._global_pps = RollingStats(60)
        self._global_window: deque = deque()

        # История алертов (cool-down)
        self._last_alert: dict = {}   # ip -> timestamp

        # Счётчики для аналитики
        self.total_analyzed = 0
        self.total_anomalies = 0

        logger.info("AnomalyDetector инициализирован (Z-score baseline)")

    # ─── Публичный API ───────────────────────────────────────────

    def analyze(self, src_ip: str, dst_port: int, payload_size: int) -> Optional[AnomalyAlert]:
        """
        Вызывать для каждого входящего пакета.
        Возвращает AnomalyAlert если обнаружена аномалия, иначе None.
        """
        self.total_analyzed += 1
        now = time.time()

        # 1. Обновляем метрики
        pps          = self._update_pps(src_ip, now)
        unique_ports = self._update_ports(src_ip, dst_port, now)
        self._payload[src_ip].add(payload_size)
        self._update_global_pps(now)

        # 2. Не детектируем до набора базы
        if self._pps[src_ip].count < self.min_samples:
            return None

        # 3. Cool-down — не спамим алертами
        if now - self._last_alert.get(src_ip, 0) < self.cool_down:
            return None

        # 4. Проверяем аномалии
        alert = (
            self._check_pps(src_ip, pps) or
            self._check_ports(src_ip, unique_ports) or
            self._check_payload(src_ip, payload_size)
        )

        if alert:
            self._last_alert[src_ip] = now
            self.total_anomalies += 1
            logger.warning(
                f"[АНОМАЛИЯ] {src_ip} | {alert.metric} | "
                f"Z={alert.z_score:.1f} | {alert.description}"
            )

        return alert

    def get_baseline_stats(self) -> dict:
        """Текущая статистика baseline — для дашборда."""
        return {
            "tracked_ips":    len(self._pps),
            "total_analyzed": self.total_analyzed,
            "total_anomalies": self.total_anomalies,
            "global_pps_mean": round(self._global_pps.mean(), 1),
            "global_pps_std":  round(self._global_pps.std(), 1),
            "per_ip": {
                ip: {
                    "pps_mean":     round(self._pps[ip].mean(), 2),
                    "pps_std":      round(self._pps[ip].std(), 2),
                    "samples":      self._pps[ip].count,
                }
                for ip in list(self._pps.keys())[:20]  # топ 20
            }
        }

    # ─── Внутренние методы ───────────────────────────────────────

    def _update_pps(self, ip: str, now: float) -> float:
        """Подсчёт пакетов в секунду для IP."""
        win = self._pkt_window[ip]
        win.append(now)
        cutoff = now - 1.0
        while win and win[0] < cutoff:
            win.popleft()
        pps = len(win)
        self._pps[ip].add(float(pps))
        return float(pps)

    def _update_ports(self, ip: str, port: int, now: float) -> int:
        """Уникальные порты за последние 10 секунд."""
        # Храним (timestamp, port) в отдельном окне
        key = f"_port_{ip}"
        win = self._pkt_window.get(key, deque())
        win.append((now, port))
        cutoff = now - 10.0
        while win and win[0][0] < cutoff:
            win.popleft()
        self._pkt_window[key] = win
        unique = len(set(p for _, p in win))
        self._ports[ip].add(float(unique))
        return unique

    def _update_global_pps(self, now: float):
        self._global_window.append(now)
        cutoff = now - 1.0
        while self._global_window and self._global_window[0] < cutoff:
            self._global_window.popleft()
        self._global_pps.add(float(len(self._global_window)))

    def _check_pps(self, ip: str, pps: float) -> Optional[AnomalyAlert]:
        stats = self._pps[ip]
        mean  = stats.mean()
        z     = stats.z_score(pps)

        # Z-score порог
        if abs(z) >= self.z_threshold and pps > mean:
            sev = "CRITICAL" if z >= 5.0 else "HIGH"
            return AnomalyAlert(
                src_ip=ip, metric="packets_per_sec",
                observed=pps, expected=mean, z_score=z,
                severity=sev,
                description=(
                    f"Трафик аномалиясы: {pps:.0f} pkt/s, "
                    f"күтілген {mean:.1f} ± {stats.std():.1f} (Z={z:.1f}σ)"
                )
            )

        # Мгновенный всплеск
        if mean > 1 and pps >= mean * self.burst_multiplier:
            return AnomalyAlert(
                src_ip=ip, metric="packets_per_sec",
                observed=pps, expected=mean,
                z_score=pps / max(mean, 1),
                severity="HIGH",
                description=(
                    f"Трафик всплескі: {pps:.0f} pkt/s "
                    f"({pps/mean:.1f}× орташадан жоғары)"
                )
            )
        return None

    def _check_ports(self, ip: str, unique_ports: int) -> Optional[AnomalyAlert]:
        stats = self._ports[ip]
        mean  = stats.mean()
        z     = stats.z_score(float(unique_ports))

        if abs(z) >= self.z_threshold and unique_ports > mean:
            return AnomalyAlert(
                src_ip=ip, metric="unique_ports",
                observed=unique_ports, expected=mean, z_score=z,
                severity="HIGH",
                description=(
                    f"Порт сканері аномалиясы: {unique_ports} бірегей порт/10с, "
                    f"күтілген {mean:.1f} (Z={z:.1f}σ)"
                )
            )
        return None

    def _check_payload(self, ip: str, size: int) -> Optional[AnomalyAlert]:
        stats = self._payload[ip]
        if stats.count < self.min_samples:
            return None
        mean = stats.mean()
        z    = stats.z_score(float(size))

        if z >= self.z_threshold and size > mean * 3:
            return AnomalyAlert(
                src_ip=ip, metric="payload_size",
                observed=size, expected=mean, z_score=z,
                severity="MEDIUM",
                description=(
                    f"Payload аномалиясы: {size} байт, "
                    f"күтілген {mean:.0f} байт (Z={z:.1f}σ) — "
                    f"деректер эксфильтрациясы?"
                )
            )
        return None
