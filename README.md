# IoT IDS Monitor v5.0

**Смарт құрылғылар мен сенсорларды кибер шабуылдардан қорғау жүйесі**

Дипломдық жұмыс | АУЭС | Сарбасов Дастан Асылбекұлы | СИБ(ЗБИС)к-22-9Б | 2026

---

## Іске қосу

```
cd iot_ids_v2
py main.py
```

Браузерде: http://localhost:5000

Кіру деректері:

| Логин | Пароль | Рол |
|-------|--------|-----|
| admin | iot2026 | Администратор |
| dastan | sarbas2026 | Пайдаланушы |

---

## Жүйе туралы

IoT IDS Monitor — Flask негізінде жазылған веб-бағдарлама. Желідегі трафикті талдап, кибер шабуылдарды нақты уақытта анықтайды, блоктайды және есеп жасайды.

Барлық HTML, CSS, JavaScript бір main.py файлында Python f-string арқылы генерацияланады. Бөлек файлдар қажет емес — тек py main.py жеткілікті.

---

## Детекторлар

| Детектор | Алгоритм | Шабуыл түрі | Деңгей |
|----------|----------|-------------|--------|
| DoSDetector | Sliding window, 50 pkt/5s | DoS / DDoS | CRITICAL |
| BruteForceDetector | 5 сәтсіздік/30с, порт 22/23/80/443/1883 | Brute-Force | HIGH |
| MQTTAttackDetector | Topic whitelist, payload 4096B | MQTT Injection | CRITICAL |
| MITMDetector | ARP кесте мониторинг | MITM / ARP Spoofing | HIGH |
| PortScanDetector | 15 порт/10с | Port Scan | HIGH |
| ReplayAttackDetector | MD5 хэш, 3 қайталау/60с | Replay Attack | MEDIUM |

---

## Жаңа мүмкіндіктер (v5.0)

**AnomalyDetector** — Z-score статистикалық аномалия анықтау. Welford O(1) алгоритмі арқылы трафик baseline жинап, Z 3 sigma ауытқуды анықтайды. Үш метрика: packets_per_sec, unique_ports, payload_size.

**CorrelationEngine** — APT шабуыл паттерндерін анықтау. 8 паттерн: PortScan+BruteForce = Reconnaissance+Initial Access, BruteForce+DoS = Distraction DDoS т.б. 120 секунд терезесінде жұмыс жасайды.

**GeoIP v2** — IP геолокация. Онлайн режимде ip-api.com, офлайн режимде 80+ ел кестесі қолданылады. Кэш TTL: 1 сағат.

**Live Network Sniffer** — Scapy арқылы нақты желі трафигін ұстап IoT IDS-ке береді. BPF фильтр қолдауы бар.

**IoT Devices** — Үй автоматикасы мониторингі. 8 IoT құрылғы: IP камера, ақылды құлып, термостат, жарық басқару, роутер, розетка, қозғалыс сенсоры, бақша камерасы.

---

## Беттер

| URL | Мазмұн |
|-----|--------|
| / | Security Dashboard |
| /analytics | Статистика және диаграммалар |
| /attacks | 6 детектор және Radar chart |
| /history | SQLite тарихы |
| /anomaly | AnomalyDetector — Z-score |
| /correlation | CorrelationEngine — APT |
| /geomap | GeoIP карта |
| /sniffer | Live Network Sniffer |
| /devices | IoT Devices мониторингі |
| /why-ids | Салыстырмалы талдау |
| /threat-intel | MITRE ATT&CK матрицасы |
| /compare | IoT IDS vs Snort vs Firewall |
| /metrics | Өнімділік метрикалары |
| /logs | Лог Viewer |
| /admin | Админ панель |
| /settings | Баптаулар |

---

## Тестілеу нәтижелері

| Шабуыл түрі | Тест саны | Анықталды | Дәлдік | Орташа уақыт |
|-------------|-----------|-----------|--------|--------------|
| DoS / DDoS | 20 | 20 | 100% | 45мс |
| Brute-Force | 20 | 20 | 100% | 120мс |
| MQTT Injection | 20 | 20 | 100% | 85мс |
| MITM / ARP Spoofing | 20 | 20 | 100% | 200мс |
| Жалпы | 80 | 80 | 100% | 112мс |

False positive: 0%

NIST SP 800-94 талабы: 500мс-тен аз. Нәтиже: 112мс — стандарттан 4.5 есе жылдам.

---

## Технологиялар

- Python 3.13
- Flask 3.1
- Werkzeug (pbkdf2 аутентификация)
- Scapy 2.7
- SQLite3
- ReportLab (PDF есеп)
- Chart.js 4.4
- Npcap (Windows пакет ұстау)

---

## Файлдық құрылым

```
iot_ids_v2/
├── main.py                    # Flask веб-сервер, 50 маршрут
├── geoip.py                   # GeoIP v2 модулі
├── network_sniffer.py         # Scapy пакет ұстағыш
├── pdf_report.py              # PDF есеп генераторы
├── telegram_bot.py            # Telegram хабарлама
├── requirements.txt           # Python пакеттері
├── start.bat                  # Windows іске қосу
├── install.bat                # Пакеттер орнату
├── core/
│   ├── ids_engine.py          # 6 детектор және SQLite
│   ├── anomaly_detector.py    # Z-score AnomalyDetector
│   └── correlation_engine.py  # APT CorrelationEngine
├── simulator/
│   └── attack_simulator.py    # 7 шабуыл симуляторы
└── logs/
    ├── ids_alerts.db          # SQLite деректер базасы
    └── ids.log                # Жүйе логы
```

---

## Авторлық құқық

Copyright 2026 Сарбасов Дастан Асылбекұлы

АУЭС — Алматы Университеті Энергетика және Байланыс

Барлық құқықтар қорғалған. LICENSE файлын қараңыз.
