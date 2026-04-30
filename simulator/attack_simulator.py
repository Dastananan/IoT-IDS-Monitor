"""
IoT Шабуыл Симуляторы — нақты IoT трафигін және шабуылдарды модельдейді
"""

import random
import time
import threading
from core.ids_engine import NetworkPacket

# Заңды IoT құрылғылары
LEGITIMATE_DEVICES = [
    "192.168.1.10",   # Смарт термостат
    "192.168.1.11",   # IP-камера
    "192.168.1.12",   # Температура датчигі
    "192.168.1.13",   # Қозғалыс датчигі
    "192.168.1.14",   # Смарт розетка
    "192.168.1.15",   # Түтін датчигі
    "192.168.1.16",   # Есік қоңырауы
    "192.168.1.17",   # Ауа сапасы датчигі
]

# Шабуылдаушы IP-лар
ATTACKER_IPS = [
    "10.0.0.99",
    "172.16.0.55",
    "203.0.113.7",
    "198.51.100.42",
    "45.33.32.156",
    "185.220.101.5",
]

MQTT_BROKER = "192.168.1.1"


def _pkt(**kwargs) -> NetworkPacket:
    return NetworkPacket(**kwargs)


# ── Заңды трафик ────────────────────────────────

def generate_normal_traffic(ids, count=1):
    """Заңды IoT трафигін генерациялайды"""
    for _ in range(count):
        ip       = random.choice(LEGITIMATE_DEVICES)
        protocol = random.choice(["MQTT", "HTTP", "TCP"])
        ids.process_packet(_pkt(
            src_ip       = ip,
            dst_ip       = MQTT_BROKER,
            protocol     = protocol,
            payload_size = random.randint(20, 512),
            port         = random.choice([1883, 8883, 80]),
            payload      = random.choice([
                "temperature=22.5", "humidity=60",
                "motion=false",     "status=online",
                "PUBLISH /sensors/data",
            ])
        ))
        time.sleep(0.01)


# ── Шабуыл симуляциялары ────────────────────────

def simulate_dos_attack(ids, attacker_ip=None, intensity=80):
    """DoS/DDoS шабуылы — массалық пакет тасқыны"""
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    for _ in range(intensity):
        ids.process_packet(_pkt(
            src_ip       = ip,
            dst_ip       = MQTT_BROKER,
            protocol     = "TCP",
            payload_size = random.randint(64, 1024),
            port         = 1883,
            payload      = "SYN_FLOOD",
            flags        = ["SYN"],
        ))


def simulate_brute_force(ids, attacker_ip=None, attempts=8):
    """Brute-Force — автоматты пароль болжау"""
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    for i in range(attempts):
        ids.process_packet(_pkt(
            src_ip       = ip,
            dst_ip       = random.choice(LEGITIMATE_DEVICES),
            protocol     = "TCP",
            payload_size = 128,
            port         = random.choice([22, 80, 443]),
            payload      = f"POST /login password=attempt_{i} 401 unauthorized auth_fail",
        ))
        time.sleep(0.05)


def simulate_mqtt_injection(ids, attacker_ip=None):
    """MQTT Injection — тыйым салынған топиктерге жазу"""
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    for topic in ["/admin/reset", "/firmware/update", "/cmd/reboot", "/$SYS/config"]:
        ids.process_packet(_pkt(
            src_ip       = ip,
            dst_ip       = MQTT_BROKER,
            protocol     = "MQTT",
            payload_size = 256,
            port         = 1883,
            payload      = f"PUBLISH {topic} payload=malicious_cmd",
        ))
        time.sleep(0.02)


def simulate_mitm_attack(ids, attacker_ip=None):
    """MITM / ARP Spoofing"""
    ip         = attacker_ip or random.choice(ATTACKER_IPS)
    victim_ip  = random.choice(LEGITIMATE_DEVICES)
    victim_mac = "AA:BB:CC:DD:EE:FF"
    fake_mac   = "11:22:33:44:55:66"

    # Алдымен заңды MAC тіркеу
    ids.process_packet(_pkt(
        src_ip=victim_ip, dst_ip="255.255.255.255",
        protocol="ARP", payload_size=64, port=0,
        payload=f"{victim_ip}:{victim_mac}", flags=["ARP"],
    ))
    time.sleep(0.1)

    # Содан кейін жалған MAC жіберу
    ids.process_packet(_pkt(
        src_ip=ip, dst_ip="255.255.255.255",
        protocol="ARP", payload_size=64, port=0,
        payload=f"{victim_ip}:{fake_mac}", flags=["ARP"],
    ))


def simulate_port_scan(ids, attacker_ip=None):
    """Port Scan — Nmap/Masscan типті порт сканерлеу"""
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    # Жиі сканерленетін порттар
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 1883, 3306, 3389, 5432, 8080, 8443,
        8883, 9200, 27017,
    ]
    for port in common_ports:
        ids.process_packet(_pkt(
            src_ip       = ip,
            dst_ip       = random.choice(LEGITIMATE_DEVICES),
            protocol     = "TCP",
            payload_size = 40,
            port         = port,
            payload      = "SYN_PROBE",
            flags        = ["SYN"],
        ))
        time.sleep(0.03)


def simulate_replay_attack(ids, attacker_ip=None):
    """Replay Attack — ескірген пакетті қайталап жіберу"""
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    # Заңды аутентификация пакетін «ұстап» қайта жіберу
    captured_payload = "AUTH_TOKEN=eyJhbGciOiJIUzI1NiJ9.dGVtcA.abc123"
    for _ in range(5):
        ids.process_packet(_pkt(
            src_ip       = ip,
            dst_ip       = MQTT_BROKER,
            protocol     = "MQTT",
            payload_size = len(captured_payload),
            port         = 1883,
            payload      = captured_payload,
        ))
        time.sleep(0.3)


def simulate_mqtt_large_payload(ids, attacker_ip=None):
    """Аномальды үлкен MQTT payload (деректер ұрлау немесе DoS)"""
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    ids.process_packet(_pkt(
        src_ip       = ip,
        dst_ip       = MQTT_BROKER,
        protocol     = "MQTT",
        payload_size = 8192,
        port         = 1883,
        payload      = "PUBLISH /sensors/data " + "X" * 8000,
    ))


# ── Сценарийлер каталогы ────────────────────────

ATTACK_SCENARIOS = {
    "dos":        ("DoS/DDoS шабуылы",          simulate_dos_attack),
    "brute":      ("Brute-Force шабуылы",        simulate_brute_force),
    "mqtt_inject":("MQTT Injection",             simulate_mqtt_injection),
    "mitm":       ("MITM / ARP Spoofing",        simulate_mitm_attack),
    "port_scan":  ("Порт сканерлеу",             simulate_port_scan),
    "replay":     ("Replay Attack",              simulate_replay_attack),
    "mqtt_flood": ("MQTT үлкен payload",         simulate_mqtt_large_payload),
}


def run_demo_scenario(ids, delay=0.5):
    """Толық демонстрациялық сценарий"""
    events = []

    def log(msg):
        events.append({"time": time.time(), "msg": msg})

    log("▶ IoT IDS демонстрациясы басталды")

    log("📡 Қалыпты трафик...")
    generate_normal_traffic(ids, count=20)
    time.sleep(delay)

    log("💥 DoS шабуылы (10.0.0.99)...")
    simulate_dos_attack(ids, attacker_ip="10.0.0.99", intensity=70)
    time.sleep(delay)

    log("🔑 Brute-Force (172.16.0.55)...")
    simulate_brute_force(ids, attacker_ip="172.16.0.55", attempts=7)
    time.sleep(delay)

    log("📨 MQTT Injection (203.0.113.7)...")
    simulate_mqtt_injection(ids, attacker_ip="203.0.113.7")
    time.sleep(delay)

    log("🕵️ MITM / ARP Spoofing (198.51.100.42)...")
    simulate_mitm_attack(ids, attacker_ip="198.51.100.42")
    time.sleep(delay)

    log("🔍 Порт сканерлеу (45.33.32.156)...")
    simulate_port_scan(ids, attacker_ip="45.33.32.156")
    time.sleep(delay)

    log("🔄 Replay Attack (185.220.101.5)...")
    simulate_replay_attack(ids, attacker_ip="185.220.101.5")
    time.sleep(delay)

    log("✅ Қалыпты трафикке оралу...")
    generate_normal_traffic(ids, count=10)

    log("✔ Демонстрация аяқталды")
    return events
