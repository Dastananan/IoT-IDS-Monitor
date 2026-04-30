"""
network_sniffer.py — Нақты желі трафигін ұстау
================================================
Scapy арқылы нақты пакеттерді ұстап, IoTIDS-ке береді.

Іске қосу (admin/root керек):
    # Windows:
    py network_sniffer.py
    py network_sniffer.py --iface "Wi-Fi" --duration 60

    # Linux/Kali:
    sudo python3 network_sniffer.py
    sudo python3 network_sniffer.py --iface eth0 --duration 60

Kali-ден шабуыл жіберу:
    hping3 -S --flood -V -p 80 <IDS_IP>           # DoS
    nmap -sS -p 1-1000 <IDS_IP>                    # Port Scan
    hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<IDS_IP>  # Brute
    mosquitto_pub -h <IDS_IP> -t /admin/cmd -m "hack"  # MQTT
"""

import sys
import time
import logging
import argparse
import threading
from datetime import datetime

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/sniffer.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# Scapy тексеру
try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ARP, ICMP, Raw,
        get_if_list, conf
    )
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    logger.error("Scapy жоқ! Орнату: pip install scapy")


class RealPacketSniffer:
    """
    Нақты желі интерфейсінен пакеттерді ұстап,
    NetworkPacket форматына айналдырып, IoTIDS-ке береді.
    """

    def __init__(self, ids, iface=None, bpf_filter="ip or arp"):
        """
        ids        — IoTIDS данасы
        iface      — желі интерфейсі (None = автоматты)
        bpf_filter — BPF фильтр (tcpdump синтаксисі)
        """
        self.ids        = ids
        self.iface      = iface
        self.bpf_filter = bpf_filter
        self.running    = False
        self._thread    = None

        # Статистика
        self.captured   = 0
        self.processed  = 0
        self.alerts_gen = 0

        # Жылдамдық шектеу (DoS симуляциясынан қорғау)
        self.max_pps    = 10000   # максимум 10K пакет/с

    def start(self):
        """Фонда sniff іске қосу."""
        if not SCAPY_OK:
            logger.error("Scapy орнатылмаған, sniffer іске қосылмады")
            return False
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(f"Sniffer іске қосылды: iface={self.iface or 'auto'}, filter='{self.bpf_filter}'")
        return True

    def stop(self):
        self.running = False
        logger.info(f"Sniffer тоқтатылды. Ұсталды: {self.captured}, Өңделді: {self.processed}, Алерт: {self.alerts_gen}")

    def get_stats(self) -> dict:
        return {
            "running":    self.running,
            "captured":   self.captured,
            "processed":  self.processed,
            "alerts_gen": self.alerts_gen,
            "iface":      self.iface or "auto",
            "filter":     self.bpf_filter,
        }

    # ── Ішкі ─────────────────────────────────────────────────────

    def _run(self):
        try:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except PermissionError:
            logger.error("Рұқсат жоқ! Windows: Admin ретінде іске қос. Linux: sudo қолдан.")
        except Exception as e:
            logger.error(f"Sniffer қатесі: {e}")

    def _on_packet(self, pkt):
        """Әр пакет үшін шақырылады."""
        self.captured += 1

        # IP пакеттері ғана
        if IP not in pkt:
            return

        # NetworkPacket форматына айналдыру
        net_pkt = self._convert(pkt)
        if not net_pkt:
            return

        self.processed += 1

        # IoTIDS-ке беру
        try:
            alerts = self.ids.process_packet(net_pkt)
            if alerts:
                self.alerts_gen += len(alerts)
                for a in alerts:
                    logger.warning(
                        f"[ALERT] {a.attack_type} | "
                        f"{a.src_ip}:{net_pkt.src_port} → {net_pkt.dst_ip}:{net_pkt.dst_port} | "
                        f"{a.severity}"
                    )
        except Exception as e:
            logger.debug(f"IDS өңдеу қатесі: {e}")

    def _convert(self, pkt):
        """Scapy пакетін NetworkPacket-ке айналдыру."""
        try:
            from core.ids_engine import NetworkPacket
        except ImportError:
            try:
                import sys, os
                sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                from core.ids_engine import NetworkPacket
            except ImportError:
                return None

        src_ip  = pkt[IP].src
        dst_ip  = pkt[IP].dst
        proto   = pkt[IP].proto   # 6=TCP, 17=UDP, 1=ICMP

        src_port = 0
        dst_port = 0
        payload_size = 0
        flags = ""

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            # TCP flags
            f = pkt[TCP].flags
            flags_map = {0x01:"F",0x02:"S",0x04:"R",0x08:"P",0x10:"A",0x20:"U"}
            flags = "".join(v for k,v in flags_map.items() if int(f) & k)
            if Raw in pkt:
                payload_size = len(bytes(pkt[Raw]))

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            if Raw in pkt:
                payload_size = len(bytes(pkt[Raw]))

        elif ICMP in pkt:
            dst_port = pkt[ICMP].type   # ICMP type as "port"

        elif ARP in pkt:
            # ARP пакеті — MITM анықтауы үшін
            src_ip  = pkt[ARP].psrc
            dst_ip  = pkt[ARP].pdst
            proto   = 0x0806

        # MQTT трафигі (1883/8883 порттар)
        protocol = "tcp"
        if dst_port in (1883, 8883) or src_port in (1883, 8883):
            protocol = "mqtt"
        elif dst_port in (22, 23):
            protocol = "ssh" if dst_port == 22 else "telnet"
        elif proto == 17:
            protocol = "udp"
        elif proto == 1:
            protocol = "icmp"

        # MQTT payload алу
        mqtt_topic   = None
        mqtt_payload = None
        if protocol == "mqtt" and Raw in pkt:
            raw = bytes(pkt[Raw])
            try:
                # MQTT PUBLISH: first byte 0x30 = PUBLISH, 0x32 = PUBLISH+QoS1
                if raw and raw[0] in (0x30, 0x32, 0x34):
                    # Topic length (bytes 2-3)
                    if len(raw) > 4:
                        tlen = (raw[2] << 8) | raw[3]
                        if 4 + tlen <= len(raw):
                            mqtt_topic = raw[4:4+tlen].decode("utf-8", errors="ignore")
                            mqtt_payload = raw[4+tlen:4+tlen+100].decode("utf-8", errors="ignore")
            except Exception:
                pass

        return NetworkPacket(
            src_ip       = src_ip,
            dst_ip       = dst_ip,
            src_port     = src_port,
            dst_port     = dst_port,
            protocol     = protocol,
            payload_size = payload_size,
            flags        = flags,
            timestamp    = time.time(),
            mqtt_topic   = mqtt_topic,
            mqtt_payload = mqtt_payload,
        )


def list_interfaces():
    """Қол жетімді интерфейстерді шығару."""
    if not SCAPY_OK:
        print("Scapy орнатылмаған!")
        return
    print("\nҚол жетімді интерфейстер:")
    for i, iface in enumerate(get_if_list()):
        print(f"  [{i}] {iface}")
    print()


def run_standalone(iface=None, duration=None, filter_str="ip or arp"):
    """
    Standalone режим — IoT IDS-пен бірге іске қосу.
    Веб-дашборд http://localhost:5000 арқылы нәтижені қарауға болады.
    """
    import os
    os.makedirs("logs", exist_ok=True)

    # IoTIDS данасын жасау
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from core.ids_engine import IoTIDS

    ids = IoTIDS()
    logger.info("IoTIDS іске қосылды")

    # Sniffer іске қосу
    sniffer = RealPacketSniffer(ids, iface=iface, bpf_filter=filter_str)
    if not sniffer.start():
        sys.exit(1)

    print("\n" + "═"*54)
    print("  IoT IDS — Real Network Sniffer")
    print("  Нақты трафик мониторингі")
    print("═"*54)
    print(f"  Интерфейс : {iface or 'автоматты'}")
    print(f"  Фильтр    : {filter_str}")
    print(f"  Уақыт     : {f'{duration}с' if duration else 'шексіз'}")
    print("═"*54)
    print("  Тоқтату: Ctrl+C\n")

    try:
        start = time.time()
        while True:
            time.sleep(5)
            s  = sniffer.get_stats()
            sm = ids.get_summary()
            elapsed = int(time.time() - start)
            print(f"  [{elapsed:4d}s] Ұсталды: {s['captured']:6d} | "
                  f"Өңделді: {s['processed']:6d} | "
                  f"Алерт: {sm['total_alerts']:4d} | "
                  f"Блок: {sm['blocked_ips']:3d} IP")

            if duration and elapsed >= duration:
                print("\n  Уақыт бітті.")
                break

    except KeyboardInterrupt:
        print("\n  Тоқтатылды.")

    finally:
        sniffer.stop()
        sm = ids.get_summary()
        print("\n" + "═"*54)
        print("  ҚОРЫТЫНДЫ")
        print("═"*54)
        print(f"  Жалпы пакет : {sniffer.captured}")
        print(f"  Өңделді     : {sniffer.processed}")
        print(f"  Алерт саны  : {sm['total_alerts']}")
        print(f"  Блок IP     : {sm['blocked_ips']}")
        if sm["attack_stats"]:
            print("  Шабуыл түрлері:")
            for at, cnt in sm["attack_stats"].items():
                print(f"    {at:<30} {cnt}")
        print("═"*54)

        # JSON есеп
        ids.export_report("logs/real_traffic_report.json")
        print("  Есеп: logs/real_traffic_report.json")
        print("═"*54 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="IoT IDS — Нақты желі трафигін тексеру"
    )
    parser.add_argument("--iface",    help="Желі интерфейсі (мысалы: eth0, Wi-Fi)")
    parser.add_argument("--duration", type=int, help="Тексеру уақыты (секунд)")
    parser.add_argument("--filter",   default="ip or arp", help="BPF фильтр")
    parser.add_argument("--list",     action="store_true", help="Интерфейстер тізімі")
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        sys.exit(0)

    run_standalone(
        iface    = args.iface,
        duration = args.duration,
        filter_str = args.filter,
    )
