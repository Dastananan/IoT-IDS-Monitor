# 🛡 IoT IDS Monitor v3.0

**Смарт құрылғылар мен сенсорларды кибер шабуылдардан қорғау жүйесі**

> Дипломдық жұмыс | АУЭС | Сарбасов Д. | СИБ(ЗБИС)к-22-9Б | 2026

---

## 🚀 Жылдам іске қосу

```
install.bat — екі рет басыңыз
```

Браузерде: **http://localhost:5000**

| Логин | Пароль | Рөл |
|-------|--------|-----|
| admin | iot2026 | Администратор |
| dastan | sarbas2026 | Пайдаланушы |

---

## 📋 Жүйе мүмкіндіктері

### 🔍 6 Детектор
| Детектор | Алгоритм | Шабуыл түрі |
|----------|----------|-------------|
| DoSDetector | Скользящее окно | DoS/DDoS |
| BruteForceDetector | Сәтсіздік счётчигі | Пароль болжау |
| MQTTAttackDetector | Топик инспекция | MQTT Injection |
| MITMDetector | ARP кесте | ARP Spoofing |
| PortScanDetector | Бірегей порт санауы | Port Scan |
| ReplayAttackDetector | MD5 хэш | Replay Attack |

### 📊 9 Веб-бет
- **/** — Нақты уақыт дашборд
- **/analytics** — Диаграммалар мен статистика
- **/attacks** — Шабуылдар радар диаграмма
- **/history** — SQLite тарихы
- **/threat-intel** — MITRE ATT&CK матрицасы
- **/compare** — IoT IDS vs Snort vs Firewall
- **/metrics** — Өнімділік метрикалары
- **/logs** — Лог Viewer
- **/admin** — Админ панель
- **/settings** — Баптаулар

---

## 🧪 Тестілеу нәтижелері

| Шабуыл | Тест | Анықталды | Дәлдік | Уақыт |
|--------|------|-----------|--------|-------|
| DoS/DDoS | 20 | 20 | **100%** | ~45мс |
| Brute-Force | 20 | 20 | **100%** | ~120мс |
| MQTT Injection | 20 | 20 | **100%** | ~85мс |
| MITM/ARP | 20 | 20 | **100%** | ~200мс |
| **Жалпы** | **80** | **80** | **100%** | ~112мс |

---

## 🛠 Технологиялар

- **Python 3.13** — негізгі тіл
- **Flask 3.1** — веб-сервер
- **SQLite** — деректер базасы
- **Chart.js 4.4** — диаграммалар
- **Inter + JetBrains Mono** — шрифттер

---

## 📁 Файлдық құрылым

```
iot_ids_v2/
├── main.py                 # Flask веб-сервер (9 бет, 21 API)
├── core/
│   └── ids_engine.py       # 6 детектор + SQLite база
├── simulator/
│   └── attack_simulator.py # 7 шабуыл симуляторы
├── telegram_bot.py         # Telegram хабарламасы
├── geoip.py                # GeoIP модулі
├── pdf_report.py           # PDF есеп генераторы
├── install.bat             # Бір рет басып орнату
├── start.bat               # Іске қосу
├── requirements.txt        # Python пакеттері
├── LICENSE                 # Авторлық құқық
└── logs/
    ├── ids.log             # Лог файл
    └── ids_alerts.db       # SQLite база
```

---

## ⚖️ Лицензия

Copyright © 2026 Сарбасов Д. — АУЭС

Барлық құқықтар қорғалған. [LICENSE](LICENSE) файлын қараңыз.
