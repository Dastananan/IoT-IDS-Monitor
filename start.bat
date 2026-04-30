@echo off
title IoT IDS v5.0 — Кіру Анықтау Жүйесі
echo.
echo ══════════════════════════════════════════════════
echo   IoT IDS Monitor v5.0
echo   AnomalyDetector + CorrelationEngine + GeoIP
echo   АУЭС - Сарбасов Д. - 2026
echo ══════════════════════════════════════════════════
echo.
cd /d "%~dp0"
echo Браузер ашылуда...
start http://localhost:5000
echo.
echo Сервер іске қосылуда... (токтату: Ctrl+C)
echo.
py main.py
pause
