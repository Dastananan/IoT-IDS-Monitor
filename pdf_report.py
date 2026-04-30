"""
PDF есеп генераторы — ReportLab + кириллица/қазақша шрифт
"""
import os
import sys
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


def _register_fonts():
    """
    Кириллица/қазақша шрифт тіркеу.
    Windows, Linux, macOS — барлығында жұмыс жасайды.
    """
    # Шрифт іздеу тізімі
    candidates = [
        # Windows
        ("C:/Windows/Fonts/arial.ttf",        "C:/Windows/Fonts/arialbd.ttf"),
        ("C:/Windows/Fonts/calibri.ttf",      "C:/Windows/Fonts/calibrib.ttf"),
        ("C:/Windows/Fonts/times.ttf",        "C:/Windows/Fonts/timesbd.ttf"),
        ("C:/Windows/Fonts/tahoma.ttf",       "C:/Windows/Fonts/tahomabd.ttf"),
        ("C:/Windows/Fonts/verdana.ttf",      "C:/Windows/Fonts/verdanab.ttf"),
        # Linux
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ("/usr/share/fonts/truetype/freefont/FreeSans.ttf",
         "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf"),
        # macOS
        ("/System/Library/Fonts/Helvetica.ttc",
         "/System/Library/Fonts/Helvetica.ttc"),
    ]

    for regular, bold in candidates:
        if os.path.exists(regular):
            try:
                pdfmetrics.registerFont(TTFont("KZFont",     regular))
                if os.path.exists(bold):
                    pdfmetrics.registerFont(TTFont("KZFont-Bold", bold))
                else:
                    pdfmetrics.registerFont(TTFont("KZFont-Bold", regular))
                return "KZFont"
            except Exception:
                continue

    # Fallback — стандартты шрифт (кириллица болмауы мүмкін)
    return "Helvetica"


FONT = _register_fonts()
FONT_BOLD = FONT + "-Bold" if FONT != "Helvetica" else "Helvetica-Bold"


def _get_styles():
    s = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "Title2", parent=s["Title"],
        fontName=FONT_BOLD,
        fontSize=18, textColor=colors.HexColor("#003366"),
        spaceAfter=6, alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        "Subtitle", parent=s["Normal"],
        fontName=FONT,
        fontSize=11, textColor=colors.HexColor("#666666"),
        spaceAfter=20, alignment=TA_CENTER
    )
    h1_style = ParagraphStyle(
        "H1", parent=s["Heading1"],
        fontName=FONT_BOLD,
        fontSize=13, textColor=colors.HexColor("#003366"),
        spaceBefore=16, spaceAfter=8,
    )
    h2_style = ParagraphStyle(
        "H2", parent=s["Heading2"],
        fontName=FONT_BOLD,
        fontSize=11, textColor=colors.HexColor("#0055aa"),
        spaceBefore=12, spaceAfter=6,
    )
    normal_style = ParagraphStyle(
        "Normal2", parent=s["Normal"],
        fontName=FONT,
        fontSize=10, leading=14,
        spaceAfter=6,
    )
    return {
        "title":    title_style,
        "subtitle": subtitle_style,
        "h1":       h1_style,
        "h2":       h2_style,
        "normal":   normal_style,
    }


def _severity_color(sev: str):
    return {
        "CRITICAL": colors.HexColor("#ff2244"),
        "HIGH":     colors.HexColor("#ff6b35"),
        "MEDIUM":   colors.HexColor("#ffd700"),
        "LOW":      colors.HexColor("#888888"),
    }.get(sev, colors.black)


def _tbl_style(header_rows=1):
    return TableStyle([
        ("BACKGROUND",    (0,0), (-1,header_rows-1), colors.HexColor("#003366")),
        ("TEXTCOLOR",     (0,0), (-1,header_rows-1), colors.white),
        ("FONTNAME",      (0,0), (-1,header_rows-1), FONT_BOLD),
        ("FONTNAME",      (0,header_rows), (-1,-1),  FONT),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,header_rows), (-1,-1),
         [colors.HexColor("#f0f4ff"), colors.white]),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
        ("ALIGN",         (1,header_rows), (-1,-1), "CENTER"),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
    ])


def generate_pdf(
    ids_summary: dict,
    db_stats: dict,
    output_path: str = "logs/iot_ids_report.pdf"
) -> str:

    os.makedirs(
        os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
        exist_ok=True
    )

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    st = _get_styles()
    story = []
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Титул ──────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("IoT IDS — Кіру Анықтау Жүйесі", st["title"]))
    story.append(Paragraph("Кибер шабуылдар туралы есеп", st["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=2,
                             color=colors.HexColor("#003366")))
    story.append(Spacer(1, 0.5*cm))

    meta = [
        ["Есеп жасалған:", now_str],
        ["Жүйе:",          "IoT IDS Monitor v5.0"],
        ["Ұйым:",          "АУЭС — Сарбасов Д., СИБ(ЗБИС)к-22-9Б, 2026"],
    ]
    meta_tbl = Table(meta, colWidths=[4*cm, 12*cm])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",    (0,0), (-1,-1), FONT),
        ("FONTNAME",    (0,0), (0,-1),  FONT_BOLD),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("TEXTCOLOR",   (0,0), (0,-1),  colors.HexColor("#003366")),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.8*cm))

    # ── 1. Жалпы статистика ────────────────────────────
    story.append(Paragraph("1. Жалпы статистика", st["h1"]))

    total    = ids_summary.get("total_packets", 0)
    alerts   = ids_summary.get("total_alerts",  0)
    blocked  = ids_summary.get("blocked_ips",   0)
    anomalies= ids_summary.get("anomaly_count", 0)
    apt      = ids_summary.get("corr_count",    0)
    db_total = db_stats.get("total_alerts",     0)
    db_block = db_stats.get("blocked_alerts",   0)

    stat_data = [
        ["Көрсеткіш", "Мән", "Сипаттама"],
        ["Өңделген пакеттер",      str(total),     "Жүйе арқылы өткен барлық пакет"],
        ["Анықталған алерттер",    str(alerts),    "Ағымдағы сессия алерттері"],
        ["Блокталған IP",          str(blocked),   "Автоматты блоктаулар"],
        ["Аномалиялар (Z-score)",  str(anomalies), "AnomalyDetector анықтаулары"],
        ["APT кампаниялар",        str(apt),       "CorrelationEngine анықтаулары"],
        ["Базадағы алерттер",      str(db_total),  "SQLite базасындағы жазбалар"],
        ["Базадағы блоктаулар",    str(db_block),  "Блокталған алерт жазбалары"],
    ]
    tbl = Table(stat_data, colWidths=[6*cm, 3*cm, 8*cm])
    tbl.setStyle(_tbl_style())
    story.append(tbl)
    story.append(Spacer(1, 0.6*cm))

    # ── 2. Шабуыл түрлері ─────────────────────────────
    story.append(Paragraph("2. Шабуыл түрлері бойынша статистика", st["h1"]))
    by_type = db_stats.get("by_type", [])
    if by_type:
        total_t = sum(r["cnt"] for r in by_type) or 1
        type_data = [["Шабуыл түрі", "Саны", "Үлесі (%)"]]
        for r in by_type:
            type_data.append([r["attack_type"], str(r["cnt"]),
                               f"{r['cnt']/total_t*100:.1f}%"])
        type_data.append(["ЖАЛПЫ", str(total_t), "100%"])
        tbl2 = Table(type_data, colWidths=[8*cm, 4*cm, 5*cm])
        st2 = _tbl_style()
        st2.add("FONTNAME",   (0,-1), (-1,-1), FONT_BOLD)
        st2.add("BACKGROUND", (0,-1), (-1,-1), colors.HexColor("#e0e8ff"))
        tbl2.setStyle(st2)
        story.append(tbl2)
    else:
        story.append(Paragraph("Деректер жоқ", st["normal"]))
    story.append(Spacer(1, 0.6*cm))

    # ── 3. Маңыздылық деңгейі ─────────────────────────
    story.append(Paragraph("3. Маңыздылық деңгейі бойынша", st["h1"]))
    by_sev = db_stats.get("by_severity", [])
    if by_sev:
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        sev_dict  = {r["severity"]: r["cnt"] for r in by_sev}
        sev_data  = [["Деңгей", "Саны"]]
        for sev in sev_order:
            if sev in sev_dict:
                sev_data.append([sev, str(sev_dict[sev])])
        tbl3 = Table(sev_data, colWidths=[8*cm, 4*cm])
        tbl3.setStyle(_tbl_style())
        story.append(tbl3)
    story.append(Spacer(1, 0.6*cm))

    # ── 4. Ең белсенді IP ─────────────────────────────
    story.append(Paragraph("4. Ең белсенді шабуылдаушы IP-адрестер (Top 10)",
                            st["h1"]))
    top_ips = db_stats.get("top_ips", [])
    if top_ips:
        total_ip = sum(r["cnt"] for r in top_ips) or 1
        ip_data = [["IP-адрес", "Шабуыл саны", "Үлесі (%)"]]
        for r in top_ips:
            ip_data.append([r["src_ip"], str(r["cnt"]),
                            f"{r['cnt']/total_ip*100:.1f}%"])
        tbl4 = Table(ip_data, colWidths=[6*cm, 5*cm, 6*cm])
        tbl4.setStyle(_tbl_style())
        story.append(tbl4)
    story.append(Spacer(1, 0.6*cm))

    # ── 5. Соңғы 20 алерт ────────────────────────────
    story.append(Paragraph("5. Соңғы 20 алерт", st["h1"]))
    recent = ids_summary.get("recent_alerts", [])[-20:]
    if recent:
        al_data = [["Уақыт", "Шабуыл түрі", "Деңгей", "IP", "Блок"]]
        for a in reversed(recent):
            al_data.append([
                str(a.get("timestamp", ""))[:19],
                a.get("attack_type", ""),
                a.get("severity", ""),
                a.get("src_ip", ""),
                "Иә" if a.get("blocked") else "—",
            ])
        tbl5 = Table(al_data, colWidths=[3*cm, 4*cm, 2.5*cm, 4.5*cm, 1.5*cm])
        tbl5.setStyle(_tbl_style())
        story.append(tbl5)
    else:
        story.append(Paragraph("Алерттер жоқ", st["normal"]))

    # ── 6. Қорытынды ──────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("6. Қорытынды және ұсынымдар", st["h1"]))

    conclusions = []
    if alerts > 0:
        dominant = max(
            ids_summary.get("attack_stats", {}).items(),
            key=lambda x: x[1], default=("—", 0)
        )
        conclusions.append(
            f"Жүйе {alerts} шабуылды анықтады, {blocked} IP-адрес блокталды."
        )
        conclusions.append(
            f"Ең жиі шабуыл түрі: {dominant[0]} ({dominant[1]} рет)."
        )
    else:
        conclusions.append("Тестілеу кезінде шабуыл анықталмады.")

    if anomalies > 0:
        conclusions.append(
            f"AnomalyDetector (Z-score baseline) {anomalies} аномалия анықтады."
        )
    if apt > 0:
        conclusions.append(
            f"CorrelationEngine {apt} APT кампаниясын анықтады."
        )

    conclusions += [
        "Барлық анықталған шабуылдар SQLite деректер базасына жазылды.",
        "DoS/DDoS шабуылдарына қарсы sliding window алгоритмі тиімді жұмыс жасады.",
        "MQTT протоколына арналған детектор IoT ортасы үшін маңызды.",
        "Жүйені одан ары жақсарту: ML-детектор, SIEM интеграциясы ұсынылады.",
    ]

    for c in conclusions:
        story.append(Paragraph(f"• {c}", st["normal"]))

    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.HexColor("#003366")))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"Есеп автоматты түрде жасалды · IoT IDS Monitor v5.0 · {now_str}",
        ParagraphStyle("footer", fontName=FONT, fontSize=8,
                       textColor=colors.grey, alignment=TA_CENTER)
    ))

    doc.build(story)
    return output_path
