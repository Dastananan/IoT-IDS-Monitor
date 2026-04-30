@echo off
chcp 65001 >nul 2>&1
title IoT IDS — Орнату

cls
echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║         IoT IDS Monitor  v3.0                   ║
echo  ║   Смарт құрылғыларды қорғау жүйесі              ║
echo  ║   АУЭС · Сарбасов Д. · 2026                     ║
echo  ╚══════════════════════════════════════════════════╝
echo.
echo  [1/4] Python тексерілуде...

python --version >nul 2>&1
if errorlevel 1 (
    py --version >nul 2>&1
    if errorlevel 1 (
        echo.
        echo  [ҚАТЕ] Python табылмады!
        echo  https://python.org сайтынан Python 3.10+ жүктеп орнатыңыз
        echo.
        pause
        exit /b 1
    )
    set PYTHON=py
) else (
    set PYTHON=python
)

echo  [OK] Python табылды
echo.
echo  [2/4] Қажетті кітапханалар орнатылуда...
echo.

%PYTHON% -m pip install flask --quiet --disable-pip-version-check
%PYTHON% -m pip install requests --quiet --disable-pip-version-check
%PYTHON% -m pip install reportlab --quiet --disable-pip-version-check

echo  [OK] Кітапханалар орнатылды
echo.
echo  [3/4] Қалталар жасалуда...

if not exist "logs" mkdir logs
if not exist "reports" mkdir reports

echo  [OK] Қалталар дайын
echo.
echo  [4/4] Жүйе іске қосылуда...
echo.
echo  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo  Браузерде мына мекенжайды аш:
echo.
echo      http://localhost:5000
echo.
echo  Кіру деректері:
echo      Логин  : admin
echo      Пароль : iot2026
echo.
echo  Жүйені тоқтату үшін: Ctrl+C
echo  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo.

timeout /t 2 >nul
start http://localhost:5000

cd /d "%~dp0"
%PYTHON% main.py

pause
