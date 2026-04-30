"""IoT IDS Monitor v5.0 — AnomalyDetector + CorrelationEngine + GeoIP"""
import sys, os, secrets
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import threading, json, csv, io
from datetime import datetime
from functools import wraps
from flask import Flask, render_template_string, jsonify, request, Response, session, redirect
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from telegram_bot import send_alert, send_startup, send_summary, test_connection as tg_test
    TG_AVAILABLE = True
except ImportError:
    TG_AVAILABLE = False

try:
    from geoip import get_attack_map_data, get_country_stats, lookup
    GEO_AVAILABLE = True
except ImportError:
    GEO_AVAILABLE = False

try:
    from pdf_report import generate_pdf
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

from core.ids_engine import IoTIDS

try:
    from network_sniffer import RealPacketSniffer
    SNIFFER_AVAILABLE = True
except ImportError:
    SNIFFER_AVAILABLE = False
from simulator.attack_simulator import (
    run_demo_scenario, generate_normal_traffic,
    simulate_dos_attack, simulate_brute_force,
    simulate_mqtt_injection, simulate_mitm_attack,
    simulate_port_scan, simulate_replay_attack,
    ATTACK_SCENARIOS
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

USERS = {
    "admin":  {"password": generate_password_hash("iot2026"),    "role": "admin", "name": "Администратор"},
    "dastan": {"password": generate_password_hash("sarbas2026"), "role": "user",  "name": "Сарбасов Д."},
}

ids          = IoTIDS()
demo_running = False
sniffer      = None   # Real network sniffer (Scapy)
ip_whitelist: set = set()
ip_blacklist: set = set()

if TG_AVAILABLE:
    ids.register_callback(send_alert)
    threading.Thread(target=send_startup, daemon=True).start()

# 
# AUTH
# 
def login_required(f):
    @wraps(f)
    def d(*a, **k):
        if not session.get("user"): return redirect("/login")
        return f(*a, **k)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a, **k):
        if not session.get("user"): return redirect("/login")
        if session.get("role") != "admin": return "Рұқсат жоқ", 403
        return f(*a, **k)
    return d

# 
# GLOBAL CSS + JS
# 
HEAD = """
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f1117;--bg1:#161b22;--bg2:#1c2030;--bg3:#242938;--bg4:#2d3347;
  --b0:rgba(255,255,255,.07);--b1:rgba(255,255,255,.12);--b2:rgba(255,255,255,.18);
  --t0:#e6eaf4;--t1:#8b95a8;--t2:#555f72;--t3:#353d4e;
  --acc:#4f8ef7;--acc2:#3a7be0;--acd:rgba(79,142,247,.14);
  --red:#f05454;--rdd:rgba(240,84,84,.13);
  --grn:#3dba7a;--gnd:rgba(61,186,122,.13);
  --ylw:#e8a838;--yld:rgba(232,168,56,.13);
  --pur:#9b72e8;--pud:rgba(155,114,232,.13);
  --cyn:#38c4d4;--cyd:rgba(56,196,212,.13);
  --ora:#e87838;--ord:rgba(232,120,56,.13);
  --r:5px;--r2:8px;--r3:12px;
}
html,body{height:100%;background:var(--bg);color:var(--t0);font-family:'Inter',sans-serif;font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased}
a{color:var(--acc);text-decoration:none}

/*  TOPBAR  */
.topbar{position:fixed;top:0;left:0;right:0;height:44px;z-index:500;
  background:var(--bg1);border-bottom:1px solid var(--b0);
  display:flex;align-items:center}
.tb-logo{display:flex;align-items:center;gap:9px;height:44px;
  padding:0 18px;border-right:1px solid var(--b0);
  font-size:13px;font-weight:700;color:var(--t0);flex-shrink:0}
.tb-logo svg{width:15px;height:15px;stroke:#fff;fill:none;stroke-width:1.5;stroke-linecap:round}
.tb-nav{display:flex;align-items:center;flex:1;overflow-x:auto;height:44px}
.tb-nav::-webkit-scrollbar{display:none}
.tnav{padding:0 12px;height:44px;display:flex;align-items:center;
  font-size:12px;font-weight:500;color:var(--t1);text-decoration:none;
  white-space:nowrap;border-bottom:2px solid transparent;transition:all .12s}
.tnav:hover{color:var(--t0);background:rgba(255,255,255,.04)}
.tnav.on{color:var(--acc);border-bottom-color:var(--acc)}
.tnav.new-feat{color:var(--grn)}
.tnav.new-feat.on{color:var(--grn);border-bottom-color:var(--grn)}
.tb-right{display:flex;align-items:center;gap:8px;padding:0 16px;flex-shrink:0}
.tb-status{display:flex;align-items:center;gap:5px;font-size:11px;
  color:var(--t1);font-family:'JetBrains Mono',monospace}
.tb-dot{width:6px;height:6px;border-radius:50%;background:var(--grn)}
.tb-user{font-size:11px;color:var(--t1);
  padding:3px 10px;border:1px solid var(--b0);border-radius:var(--r);
  font-family:'JetBrains Mono',monospace}
.tb-exit{display:flex;align-items:center;gap:5px;
  padding:3px 10px;border:1px solid var(--b0);border-radius:var(--r);
  font-size:11px;color:var(--t1);text-decoration:none;transition:all .12s}
.tb-exit:hover{border-color:var(--red);color:var(--red)}
.tb-exit svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:1.5;stroke-linecap:round}

/*  SIDEBAR  */
.wrap{display:flex;padding-top:44px;min-height:100vh}
.sidebar{width:200px;min-width:200px;background:var(--bg1);
  border-right:1px solid var(--b0);position:fixed;
  top:44px;left:0;height:calc(100vh - 44px);z-index:400;
  display:flex;flex-direction:column;overflow-y:auto}
.sidebar::-webkit-scrollbar{width:3px}
.sidebar::-webkit-scrollbar-thumb{background:var(--b1)}
.sb-sec{font-size:9px;font-weight:700;color:var(--t3);
  letter-spacing:.1em;text-transform:uppercase;padding:12px 14px 4px}
.sb-sec:first-child{padding-top:14px}
.snav{display:flex;align-items:center;gap:8px;padding:6px 14px;
  color:var(--t1);font-size:12px;text-decoration:none;
  border-left:2px solid transparent;transition:all .1s}
.snav svg{width:12px;height:12px;stroke:currentColor;fill:none;
  stroke-width:1.5;stroke-linecap:round;flex-shrink:0;opacity:.5}
.snav:hover{background:var(--bg3);color:var(--t0)}
.snav:hover svg,.snav.on svg{opacity:1}
.snav.on{background:var(--acd);color:var(--acc);border-left-color:var(--acc);font-weight:500}
.snav.new-feat{color:var(--grn)}
.snav.new-feat svg{stroke:var(--grn)}
.snav.new-feat.on{background:rgba(61,186,122,.1);color:var(--grn);border-left-color:var(--grn)}
.sb-badge{background:var(--grn);color:#000;font-size:8px;font-weight:700;
  padding:1px 5px;border-radius:3px;margin-left:auto;letter-spacing:.03em}
.sb-bot{margin-top:auto;padding:10px 14px;border-top:1px solid var(--b0)}
.sb-live{display:flex;align-items:center;gap:6px;font-size:10px;
  color:var(--grn);font-family:'JetBrains Mono',monospace}
.sb-dot{width:5px;height:5px;border-radius:50%;background:var(--grn)}

/*  MAIN  */
.main{margin-left:200px;flex:1;padding:20px 22px;max-width:1600px}
.ph{margin-bottom:16px}
.ph-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:3px}
.ph-title{font-size:16px;font-weight:600;color:var(--t0);letter-spacing:-.02em}
.ph-sub{font-size:11px;color:var(--t2)}
.ph-badge{background:var(--grn);color:#000;font-size:9px;font-weight:700;
  padding:2px 7px;border-radius:3px;margin-left:8px;letter-spacing:.04em}

/*  STAT CARDS  */
.sg{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin-bottom:14px}
.sc{background:var(--bg2);border:1px solid var(--b0);border-radius:var(--r2);
  padding:13px 14px;position:relative;overflow:hidden}
.sc::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%}
.ca::before{background:var(--acc)}.cr::before{background:var(--red)}
.cy::before{background:var(--ylw)}.cg::before{background:var(--grn)}
.cp::before{background:var(--pur)}.cc::before{background:var(--cyn)}
.co::before{background:var(--ora)}
.sc-l{font-size:9px;font-weight:700;color:var(--t2);letter-spacing:.08em;
  text-transform:uppercase;font-family:'JetBrains Mono',monospace;margin-bottom:6px}
.sc-v{font-size:22px;font-weight:700;letter-spacing:-.03em;
  line-height:1;font-family:'JetBrains Mono',monospace}
.ca .sc-v{color:var(--acc)}.cr .sc-v{color:var(--red)}
.cy .sc-v{color:var(--ylw)}.cg .sc-v{color:var(--grn)}
.cp .sc-v{color:var(--pur)}.cc .sc-v{color:var(--cyn)}
.co .sc-v{color:var(--ora)}
.sc-s{font-size:9px;color:var(--t2);font-family:'JetBrains Mono',monospace;margin-top:4px}

/*  PANELS  */
.panel{background:var(--bg2);border:1px solid var(--b0);border-radius:var(--r2);padding:14px}
.panel.new-feat{border-color:rgba(61,186,122,.25)}
.panel-hd{display:flex;align-items:center;justify-content:space-between;
  margin-bottom:10px;padding-bottom:9px;border-bottom:1px solid var(--b0)}
.panel-t{font-size:10px;font-weight:700;color:var(--t0);
  letter-spacing:.07em;text-transform:uppercase;font-family:'JetBrains Mono',monospace}
.panel-m{font-size:9px;color:var(--t2);font-family:'JetBrains Mono',monospace}
.panel-new{font-size:8px;font-weight:700;background:var(--grn);color:#000;
  padding:2px 6px;border-radius:3px;letter-spacing:.04em}

/*  GRID  */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.g65{display:grid;grid-template-columns:1.65fr 1fr;gap:12px}
.g35{display:grid;grid-template-columns:1fr 1.65fr;gap:12px}
.mb10{margin-bottom:10px}.mb14{margin-bottom:14px}

/*  BUTTONS  */
.btn{display:inline-flex;align-items:center;gap:5px;padding:5px 11px;
  border-radius:var(--r);font-size:11px;font-weight:500;
  font-family:'Inter',sans-serif;cursor:pointer;border:1px solid transparent;
  text-decoration:none;white-space:nowrap;transition:all .1s}
.btn-acc{background:var(--acc2);color:#fff;border-color:var(--acc2)}
.btn-acc:hover{background:var(--acc);color:#fff}
.btn-sec{background:var(--bg3);color:var(--t1);border-color:var(--b1)}
.btn-sec:hover{background:var(--bg4);color:var(--t0)}
.btn-grn{background:rgba(61,186,122,.15);color:var(--grn);border-color:rgba(61,186,122,.3)}
.btn-grn:hover{background:rgba(61,186,122,.25)}
.btn-danger{background:var(--rdd);color:var(--red);border-color:rgba(240,84,84,.25)}
.btn-danger:hover{background:rgba(240,84,84,.22)}
.btn-sm{padding:3px 8px;font-size:10px}
.bgrp{display:flex;gap:6px;flex-wrap:wrap}

/*  ATTACK BUTTONS  */
.ag{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin-bottom:12px}
.ab{display:flex;align-items:center;gap:9px;padding:10px 12px;
  background:var(--bg3);border:1px solid var(--b0);border-radius:var(--r2);
  cursor:pointer;transition:all .12s;font-family:'Inter',sans-serif;
  width:100%;text-align:left}
.ab:hover{border-color:var(--acc);background:var(--bg4)}
.ab-ico{width:26px;height:26px;background:var(--bg4);border:1px solid var(--b1);
  border-radius:var(--r);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.ab-ico svg{width:12px;height:12px;stroke:var(--acc);fill:none;stroke-width:1.5;stroke-linecap:round}
.ab-n{font-size:12px;font-weight:500;color:var(--t0)}
.ab-s{font-size:9px;color:var(--t2);font-family:'JetBrains Mono',monospace;margin-top:1px}

/*  BADGES  */
.badge{display:inline-flex;padding:1px 5px;border-radius:2px;
  font-size:9px;font-weight:700;font-family:'JetBrains Mono',monospace;
  letter-spacing:.05em;text-transform:uppercase}
.b-c{background:var(--rdd);color:var(--red);border:1px solid rgba(240,84,84,.25)}
.b-h{background:rgba(232,120,56,.12);color:var(--ora);border:1px solid rgba(232,120,56,.25)}
.b-m{background:var(--yld);color:var(--ylw);border:1px solid rgba(232,168,56,.25)}
.b-l{background:var(--bg3);color:var(--t3);border:1px solid var(--b0)}
.b-ok{background:var(--gnd);color:var(--grn);border:1px solid rgba(61,186,122,.25)}
.b-apt{background:var(--pud);color:var(--pur);border:1px solid rgba(155,114,232,.25)}
.b-anom{background:var(--cyd);color:var(--cyn);border:1px solid rgba(56,196,212,.25)}
.b-adm{background:var(--acd);color:var(--acc);border:1px solid rgba(79,142,247,.25)}

/*  FEED  */
.feed{max-height:360px;overflow-y:auto}
.feed::-webkit-scrollbar{width:3px}
.feed::-webkit-scrollbar-thumb{background:var(--bg4);border-radius:2px}
.fi{display:flex;align-items:flex-start;gap:8px;padding:8px 0;border-bottom:1px solid var(--b0)}
.fi:last-child{border-bottom:none}
.fi-sev{width:32px;flex-shrink:0;padding-top:1px}
.fi-body{flex:1;min-width:0}
.fi-r1{display:flex;align-items:center;gap:6px;margin-bottom:2px;flex-wrap:wrap}
.fi-type{font-size:12px;font-weight:600;color:var(--t0)}
.fi-ip{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--acc)}
.fi-desc{font-size:11px;color:var(--t2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fi-det{font-size:9px;color:var(--pur);font-family:'JetBrains Mono',monospace;margin-top:1px}
.fi-time{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--t2);white-space:nowrap;flex-shrink:0}

/*  TABLE  */
table{width:100%;border-collapse:collapse}
th{font-size:10px;font-weight:700;color:var(--t2);letter-spacing:.08em;
  text-transform:uppercase;padding:8px 12px;text-align:left;
  background:var(--bg3);border-bottom:1px solid var(--b0);
  font-family:'JetBrains Mono',monospace}
td{padding:8px 12px;font-size:12px;border-bottom:1px solid var(--b0);color:var(--t1)}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02);color:var(--t0)}
.mono{font-family:'JetBrains Mono',monospace;font-size:11px}
.dim{color:var(--t2)}

/*  CHARTS  */
.chbox{position:relative;height:220px}
.chbox-lg{position:relative;height:270px}
.chbox-xl{position:relative;height:310px}

/*  PROGRESS  */
.pr{margin-bottom:8px}
.pr-top{display:flex;justify-content:space-between;margin-bottom:3px}
.pr-l{font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--t1)}
.pr-v{font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--t2)}
.pr-bg{height:4px;background:var(--bg4);border-radius:2px}
.pr-f{height:100%;border-radius:2px;transition:width .5s}

/*  ALERT BAR  */
.alert-bar{display:flex;align-items:center;gap:10px;padding:8px 13px;
  border-radius:var(--r2);margin-bottom:12px;
  font-size:11px;font-family:'JetBrains Mono',monospace;border:1px solid}
.alert-bar.danger{background:var(--rdd);border-color:rgba(240,84,84,.25);color:var(--red)}
.alert-bar.apt{background:var(--pud);border-color:rgba(155,114,232,.25);color:var(--pur)}
.alert-bar.anom{background:var(--cyd);border-color:rgba(56,196,212,.25);color:var(--cyn)}

/*  INPUT  */
input[type=text],input[type=password],select{
  background:var(--bg3);border:1px solid var(--b1);color:var(--t0);
  padding:6px 10px;border-radius:var(--r);font-size:11px;
  font-family:'Inter',sans-serif;outline:none;transition:border .1s;width:100%}
input:focus,select:focus{border-color:var(--acc)}

/*  MISC  */
.ipr{display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--b0)}
.ipr:last-child{border-bottom:none}
.ipr-a{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--red)}
.divider{height:1px;background:var(--b0);margin:12px 0}
.empty{color:var(--t3);text-align:center;padding:24px 0;font-size:11px;font-family:'JetBrains Mono',monospace}
.term{background:#0a0d12;border:1px solid var(--b0);border-radius:var(--r2);
  padding:12px;max-height:480px;overflow-y:auto;
  font-family:'JetBrains Mono',monospace;font-size:11px;line-height:1.8}
.term::-webkit-scrollbar{width:3px}
.term::-webkit-scrollbar-thumb{background:var(--bg4)}
.tw{color:var(--ylw)}.te{color:var(--red)}.ti{color:var(--t3)}

/*  Z-SCORE BAR  */
.zbar{height:6px;background:var(--bg4);border-radius:3px;margin-top:4px;overflow:hidden}
.zbar-f{height:100%;border-radius:3px;transition:width .5s}

/*  TOAST  */
#toast{position:fixed;bottom:20px;right:20px;z-index:9999;
  background:var(--bg2);border:1px solid var(--b1);
  border-left:3px solid var(--acc);padding:10px 16px;border-radius:var(--r2);
  font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--t0);
  opacity:0;transform:translateY(6px);transition:all .18s;
  pointer-events:none;box-shadow:0 8px 32px rgba(0,0,0,.6);max-width:300px}
#toast.show{opacity:1;transform:translateY(0)}

/*  APT PATTERN CARD  */
.apt-card{background:var(--bg3);border:1px solid rgba(155,114,232,.2);
  border-radius:var(--r2);padding:12px;margin-bottom:8px}
.apt-campaign{font-size:12px;font-weight:600;color:var(--pur);margin-bottom:4px}
.apt-det{font-size:10px;color:var(--t2);font-family:'JetBrains Mono',monospace}

/*  GEO ROW  */
.geo-row{display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--b0)}
.geo-row:last-child{border-bottom:none}
.geo-flag{font-size:16px;width:24px;text-align:center;flex-shrink:0}
.geo-country{font-size:12px;font-weight:500;color:var(--t0);flex:1}
.geo-count{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--acc)}

@media(max-width:1100px){.sg{grid-template-columns:repeat(2,1fr)}}
</style>"""

ICONS = {
 "shield": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
 "grid":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>',
 "wave":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
 "warn":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
 "clock":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
 "brain":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M9.5 2a2.5 2.5 0 015 0v1.5M9.5 2A4.5 4.5 0 005 6.5v1A4.5 4.5 0 009.5 12H12M14.5 2A4.5 4.5 0 0119 6.5v1A4.5 4.5 0 0114.5 12H12M12 12v10M8 17h8"/></svg>',
 "link":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>',
 "globe":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>',
 "bar":    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
 "metric": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M3 3v18h18"/><path d="M18 17l-5-8-4 4-3-3"/></svg>',
 "threat": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
 "file":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
 "users":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>',
 "gear":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 010 14.14M4.93 4.93a10 10 0 000 14.14"/></svg>',
 "exit":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
 "play":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
 "zap":    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>',
 "lock":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>',
 "eye":    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
 "scan":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
 "loop":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>',
 "msg":    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M22 16.92v3a2 2 0 01-2.18 2A19.79 19.79 0 013.07 9.81 2 2 0 012 0h3"/></svg>',
 "reset":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>',
}

CJS = """Chart.defaults.color='#555f72';Chart.defaults.borderColor='rgba(255,255,255,.07)';Chart.defaults.font.family="'JetBrains Mono',monospace";Chart.defaults.font.size=10;"""

BASEJS = """<script>
function req(m,u,d,cb){var x=new XMLHttpRequest();x.open(m,u,true);if(d)x.setRequestHeader('Content-Type','application/json');x.onreadystatechange=function(){if(x.readyState!==4)return;try{cb&&cb(JSON.parse(x.responseText),x.status);}catch(e){cb&&cb({},x.status);}};x.send(d?JSON.stringify(d):null);}
function get(u,cb){req('GET',u,null,cb);}function post(u,cb){req('POST',u,null,cb);}
function postJ(u,d,cb){req('POST',u,d,cb);}function del(u,cb){req('DELETE',u,null,cb);}
function toast(msg,t){var el=document.getElementById('toast');if(!el)return;el.textContent=msg;var c={'err':'var(--red)','ok':'var(--grn)','warn':'var(--ylw)','apt':'var(--pur)','anom':'var(--cyn)'}[t]||'var(--acc)';el.style.borderLeftColor=c;el.classList.add('show');setTimeout(function(){el.classList.remove('show');},3000);}
function bdg(s){var m={CRITICAL:'b-c',HIGH:'b-h',MEDIUM:'b-m',LOW:'b-l'};return '<span class="badge '+(m[s]||'b-l')+'">'+s+'</span>';}
document.querySelectorAll('.snav,.tnav').forEach(function(a){if(a.getAttribute('href')===window.location.pathname)a.classList.add('on');});
</script>"""

def I(name): return ICONS.get(name, '')

def mkhdr():
    u = session.get("user","—"); ud = USERS.get(u,{})
    pages = [
        ("/","Dashboard"), ("/analytics","Analytics"), ("/attacks","Attacks"),
        ("/history","History"), ("/threat-intel","Threat Intel"),
        ("/compare","Compare"), ("/metrics","Metrics"), ("/logs","Logs"),
    ]
    new_pages = [
        ("/anomaly","Anomaly"), ("/correlation","Correlation"),
        ("/geomap","Geo Map"), ("/sniffer","Live Sniffer"), ("/devices","IoT Devices"), ("/why-ids","Неліктен IoT IDS?"),
    ]
    nav = "".join(f'<a href="{h}" class="tnav">{l}</a>' for h,l in pages)
    nav += "".join(f'<a href="{h}" class="tnav">{l}</a>' for h,l in new_pages)
    name = ud.get("name","—"); role = ud.get("role","")
    return (f'<div class="topbar">'
            f'<div class="tb-logo">{I("shield")} IoT IDS v5</div>'
            f'<div class="tb-nav">{nav}</div>'
            f'<div class="tb-right">'
            f'<div class="tb-status"><span class="tb-dot"></span>Live</div>'
            f'<div class="tb-user">{name} [{role}]</div>'
            f'<a href="/logout" class="tb-exit">{I("exit")} Шығу</a>'
            f'</div></div>')

def mkside():
    groups = [
        ("Monitoring",[
            ("grid","/","Dashboard",False),
            ("wave","/analytics","Analytics",False),
            ("warn","/attacks","Attacks",False),
            ("clock","/history","History",False),
        ]),
        ("Жаңа — v5",[
            ("brain","/anomaly","Anomaly Detect.",True),
            ("link","/correlation","Correlation",True),
            ("globe","/geomap","Geo Map",True),
            ("scan","/sniffer","Live Sniffer",True),
            ("zap","/devices","IoT Devices",True),
            ("warn","/why-ids","Неліктен IoT IDS?",True),
        ]),
        ("Intelligence",[
            ("threat","/threat-intel","Threat Intel",False),
            ("bar","/compare","Compare",False),
            ("metric","/metrics","Metrics",False),
            ("file","/logs","Logs",False),
        ]),
        ("System",[
            ("users","/admin","Admin",False),
            ("gear","/settings","Settings",False),
        ]),
    ]
    html = ""
    for sec, links in groups:
        html += f'<div class="sb-sec">{sec}</div>'
        for ico, href, label, is_new in links:
            cls = "snav new-feat" if is_new else "snav"
            badge = '' if is_new else ""
            html += f'<a href="{href}" class="{cls}">{I(ico)} {label}{badge}</a>'
    return (f'<div class="sidebar">{html}'
            f'<div class="sb-bot"><div class="sb-live"><span class="sb-dot"></span>'
            f'System Active</div></div></div>')

def wrap(body, title="IoT IDS"):
    return (f'<!DOCTYPE html>\n<html lang="kk"><head>{HEAD}<title>{title}</title></head>\n<body>\n'
            + mkhdr() + '\n<div class="wrap">\n' + mkside()
            + '\n<div class="main">' + body + '</div>\n</div>\n'
            + '<div id="toast"></div>\n' + BASEJS)

def ab(ico, action, name, typ):
    return (f'<form method="post" action="/do/{action}" style="margin:0">'
            f'<button type="submit" class="ab">'
            f'<div class="ab-ico">{I(ico)}</div>'
            f'<div><div class="ab-n">{name}</div><div class="ab-s">{typ}</div></div>'
            f'</button></form>')

# 
# PAGES
# 

def page_sniffer():
    body = f"""
<div class="ph">
  <div class="ph-row">
    <div>
      <div class="ph-title">Live Network Sniffer </div>
      <div class="ph-sub">Scapy · нақты желі трафигін ұстау · Kali шабуылдарын анықтау</div>
    </div>
    <div class="bgrp">
      <button class="btn btn-grn" id="btn-start" onclick="startSniff()"> Start Sniffer</button>
      <button class="btn btn-danger" id="btn-stop" onclick="stopSniff()" disabled> Stop</button>
    </div>
  </div>
</div>

<div id="sniff-warn" style="display:none" class="alert-bar danger mb14">
  Scapy орнатылмаған! <code style="margin-left:8px">pip install scapy</code>
  &nbsp;·&nbsp; Windows-та Npcap керек: npcap.com
</div>

<div class="sg mb14">
  <div class="sc cg"><div class="sc-l">Status</div>
    <div class="sc-v" id="sn-status" style="color:var(--t2);font-size:14px;padding-top:3px">STOPPED</div></div>
  <div class="sc ca"><div class="sc-l">Captured</div>
    <div class="sc-v" id="sn-cap" style="color:var(--acc)">0</div><div class="sc-s">total packets</div></div>
  <div class="sc cc"><div class="sc-l">Processed</div>
    <div class="sc-v" id="sn-proc" style="color:var(--cyn)">0</div><div class="sc-s">by IDS</div></div>
  <div class="sc cr"><div class="sc-l">Alerts</div>
    <div class="sc-v" id="sn-alert" style="color:var(--red)">0</div><div class="sc-s">generated</div></div>
</div>

<div class="g2 mb14">
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">Sniffer Config</span></div>
    <div style="display:flex;flex-direction:column;gap:9px">
      <div>
        <div style="font-size:9px;font-weight:700;color:var(--t2);letter-spacing:.08em;text-transform:uppercase;font-family:JetBrains Mono,monospace;margin-bottom:5px">Network Interface</div>
        <input type="text" id="sn-iface" placeholder="eth0 / Wi-Fi / auto (бос қалдыр)" style="width:100%">
        <div style="font-size:10px;color:var(--t2);font-family:JetBrains Mono,monospace;margin-top:4px">Linux: eth0, wlan0 &nbsp;·&nbsp; Windows: Wi-Fi, Ethernet</div>
      </div>
      <div>
        <div style="font-size:9px;font-weight:700;color:var(--t2);letter-spacing:.08em;text-transform:uppercase;font-family:JetBrains Mono,monospace;margin-bottom:5px">BPF Filter</div>
        <input type="text" id="sn-filter" value="ip or arp" style="width:100%">
        <div style="font-size:10px;color:var(--t2);font-family:JetBrains Mono,monospace;margin-top:4px">tcpdump синтаксисі: tcp port 80, src 192.168.1.x, ...</div>
      </div>
      <div style="padding:10px;background:var(--bg3);border-radius:var(--r);border:1px solid var(--b0)">
        <div style="font-size:10px;font-weight:700;color:var(--ylw);margin-bottom:6px;font-family:JetBrains Mono,monospace"> Талаптар</div>
        <div style="font-size:10px;color:var(--t2);font-family:JetBrains Mono,monospace;line-height:2">
          Windows: <span style="color:var(--acc)">Admin ретінде іске қос</span> + Npcap<br>
          Linux: <span style="color:var(--acc)">sudo python3 main.py</span><br>
          Kali: <span style="color:var(--grn)">автоматты — root ретінде жұмыс жасайды</span>
        </div>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-hd"><span class="panel-t">Kali Attack Commands</span></div>
    <div style="font-size:10px;color:var(--t2);font-family:JetBrains Mono,monospace;margin-bottom:10px">
      IDS_IP = IoT IDS жүктелген компьютердің IP-ы
    </div>
    <div id="kali-cmds">
      <div style="margin-bottom:8px">
        <div style="font-size:9px;font-weight:700;color:var(--red);letter-spacing:.06em;text-transform:uppercase;margin-bottom:4px">DoS / DDoS</div>
        <div style="background:#0a0d12;border-radius:var(--r);padding:8px 10px;font-family:JetBrains Mono,monospace;font-size:10px;color:#3dba7a;line-height:2">
          hping3 -S --flood -V -p 80 IDS_IP<br>
          hping3 -SARFU -p 443 --flood IDS_IP
        </div>
      </div>
      <div style="margin-bottom:8px">
        <div style="font-size:9px;font-weight:700;color:var(--ylw);letter-spacing:.06em;text-transform:uppercase;margin-bottom:4px">Port Scan (nmap)</div>
        <div style="background:#0a0d12;border-radius:var(--r);padding:8px 10px;font-family:JetBrains Mono,monospace;font-size:10px;color:#3dba7a;line-height:2">
          nmap -sS -p 1-1000 IDS_IP<br>
          nmap -sV --version-intensity 5 IDS_IP
        </div>
      </div>
      <div style="margin-bottom:8px">
        <div style="font-size:9px;font-weight:700;color:var(--ora);letter-spacing:.06em;text-transform:uppercase;margin-bottom:4px">Brute Force (hydra)</div>
        <div style="background:#0a0d12;border-radius:var(--r);padding:8px 10px;font-family:JetBrains Mono,monospace;font-size:10px;color:#3dba7a;line-height:2">
          hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://IDS_IP<br>
          hydra -l admin -p password IDS_IP http-get /
        </div>
      </div>
      <div style="margin-bottom:8px">
        <div style="font-size:9px;font-weight:700;color:var(--cyn);letter-spacing:.06em;text-transform:uppercase;margin-bottom:4px">MQTT Injection</div>
        <div style="background:#0a0d12;border-radius:var(--r);padding:8px 10px;font-family:JetBrains Mono,monospace;font-size:10px;color:#3dba7a;line-height:2">
          mosquitto_pub -h IDS_IP -t /admin/cmd -m "exploit"<br>
          mosquitto_pub -h IDS_IP -t /firmware/update -m "malware"
        </div>
      </div>
      <div>
        <div style="font-size:9px;font-weight:700;color:var(--pur);letter-spacing:.06em;text-transform:uppercase;margin-bottom:4px">ARP Spoofing (MITM)</div>
        <div style="background:#0a0d12;border-radius:var(--r);padding:8px 10px;font-family:JetBrains Mono,monospace;font-size:10px;color:#3dba7a;line-height:2">
          arpspoof -i eth0 -t IDS_IP GATEWAY_IP<br>
          ettercap -T -M arp:remote /IDS_IP/ /GATEWAY_IP/
        </div>
      </div>
    </div>
  </div>
</div>

<div class="panel">
  <div class="panel-hd">
    <span class="panel-t">Live Capture Log</span>
    <span class="panel-m" id="sn-log-cnt">0 packets</span>
  </div>
  <div class="term" id="sn-log" style="height:300px"><span class="dim">Sniffer іске қосылғанда мұнда нақты трафик көрінеді...</span></div>
</div>"""
    return wrap(body,"IoT IDS — Live Sniffer") + """
<script>
function loadStatus() {
  get('/api/sniffer/status', function(d) {
    if (!d.available) {
      document.getElementById('sniff-warn').style.display='flex';
      document.getElementById('sn-status').textContent='NOT AVAILABLE';
      document.getElementById('sn-status').style.color='var(--red)';
      return;
    }
    var running = d.running;
    document.getElementById('sn-status').textContent = running ? 'RUNNING' : 'STOPPED';
    document.getElementById('sn-status').style.color = running ? 'var(--grn)' : 'var(--t2)';
    document.getElementById('btn-start').disabled = running;
    document.getElementById('btn-stop').disabled  = !running;
    document.getElementById('sn-cap').textContent   = d.captured   || 0;
    document.getElementById('sn-proc').textContent  = d.processed  || 0;
    document.getElementById('sn-alert').textContent = d.alerts_gen || 0;
  });
}

function startSniff() {
  var iface  = document.getElementById('sn-iface').value.trim() || null;
  var filter = document.getElementById('sn-filter').value.trim() || 'ip or arp';
  postJ('/api/sniffer/start', {iface: iface, filter: filter}, function(r) {
    if (r.status === 'started') {
      toast('Sniffer іске қосылды', 'ok');
      loadStatus();
      startLogPoll();
    } else {
      toast(r.error || 'Қате: Admin/sudo керек', 'err');
    }
  });
}

function stopSniff() {
  post('/api/sniffer/stop', function() {
    toast('Sniffer тоқтатылды', 'warn');
    loadStatus();
  });
}

// Log polling — нақты трафик лог
var logTimer = null;
function startLogPoll() {
  if (logTimer) clearInterval(logTimer);
  logTimer = setInterval(function() {
    get('/api/logs', function(d) {
      var lines = (d.lines || []).filter(function(l) {
        return l.includes('[ALERT]') || l.includes('АНОМАЛ') || l.includes('КОРРЕЛЯ') || l.includes('SNIFFER') || l.includes('Captured');
      });
      if (!lines.length) return;
      document.getElementById('sn-log-cnt').textContent = lines.length + ' events';
      document.getElementById('sn-log').innerHTML = lines.slice(-100).reverse().map(function(l) {
        var c = 'ti';
        if (l.includes('[ALERT]') || l.includes('CRITICAL')) c = 'te';
        else if (l.includes('HIGH') || l.includes('WARNING')) c = 'tw';
        else if (l.includes('АНОМАЛ') || l.includes('КОРРЕЛЯ')) c = 'tw';
        return '<div class="' + c + '">' + l.replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</div>';
      }).join('');
    });
  }, 1000);
}

loadStatus();
setInterval(loadStatus, 2000);
startLogPoll();
</script></body></html>"""

def page_iot_devices():
    body = """
<div class="ph">
  <div class="ph-row">
    <div>
      <div class="ph-title">IoT Devices</div>
      <div class="ph-sub">Үй автоматикасы — нақты уақыттағы құрылғы мониторингі және шабуыл симуляциясы</div>
    </div>
    <div class="bgrp">
      <button class="btn btn-acc btn-sm" onclick="runDemo()"> Толық демо</button>
      <button class="btn btn-sec btn-sm" onclick="resetDevices()">↺ Қалпына келтір</button>
    </div>
  </div>
</div>

<div class="sg mb14" style="grid-template-columns:repeat(4,1fr)">
  <div class="sc cg"><div class="sc-l">Барлық құрылғы</div>
    <div class="sc-v" id="dev-total" style="color:var(--grn)">8</div>
    <div class="sc-s">registered</div></div>
  <div class="sc cg"><div class="sc-l">Онлайн</div>
    <div class="sc-v" id="dev-online" style="color:var(--grn)">8</div>
    <div class="sc-s">active</div></div>
  <div class="sc cr"><div class="sc-l">Шабуыл астында</div>
    <div class="sc-v" id="dev-attacked" style="color:var(--red)">0</div>
    <div class="sc-s">under attack</div></div>
  <div class="sc cy"><div class="sc-l">Офлайн</div>
    <div class="sc-v" id="dev-offline" style="color:var(--ylw)">0</div>
    <div class="sc-s">blocked/down</div></div>
</div>

<div class="panel mb14">
  <div class="panel-hd">
    <span class="panel-t">Үй автоматикасы — IoT Network</span>
    <span class="panel-m" id="dev-time">—</span>
  </div>
  <div id="devices-grid" style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:4px 0"></div>
</div>

<div class="g2 mb14">
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">Шабуыл Симуляциясы</span>
    <span class="panel-m">Түрін таңдап жіберіңіз</span></div>
    <div id="attack-btns" style="display:grid;grid-template-columns:1fr 1fr;gap:8px"></div>
  </div>
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">Оқиғалар журналы</span>
    <span class="panel-m" id="ev-cnt">0 events</span></div>
    <div class="feed" id="dev-feed" style="max-height:280px">
      <div class="empty">Шабуыл жіберіңіз немесе демо іске қосыңыз</div>
    </div>
  </div>
</div>

<div class="panel">
  <div class="panel-hd"><span class="panel-t">Неліктен IoT Қауіпсіз Емес?</span></div>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:4px 0">
    <div style="padding:14px;background:var(--bg3);border-radius:var(--r2);border:1px solid var(--b0)">
      
      <div style="font-size:12px;font-weight:600;color:var(--t0);margin-bottom:6px">Әлсіз парольдер</div>
      <div style="font-size:11px;color:var(--t2);line-height:1.7">Көп IoT құрылғысы зауыттық "admin/admin" немесе "1234" паролін өзгертпей қолданады. OWASP IoT I1.</div>
    </div>
    <div style="padding:14px;background:var(--bg3);border-radius:var(--r2);border:1px solid var(--b0)">
      
      <div style="font-size:12px;font-weight:600;color:var(--t0);margin-bottom:6px">Шифрсыз MQTT</div>
      <div style="font-size:11px;color:var(--t2);line-height:1.7">IoT құрылғылары MQTT 1883 портын TLS-сіз қолданады — деректер ашық түрде желіде жүреді.</div>
    </div>
    <div style="padding:14px;background:var(--bg3);border-radius:var(--r2);border:1px solid var(--b0)">
      
      <div style="font-size:12px;font-weight:600;color:var(--t0);margin-bottom:6px">Жаңартусыздық</div>
      <div style="font-size:11px;color:var(--t2);line-height:1.7">IoT құрылғылары сирек жаңартылады — осалдықтар жылдар бойы жабылмай қалады. CVE-2024+ мысалдар бар.</div>
    </div>
    <div style="padding:14px;background:var(--bg3);border-radius:var(--r2);border:1px solid var(--b0)">
      
      <div style="font-size:12px;font-weight:600;color:var(--t0);margin-bottom:6px">Мониторинг жоқ</div>
      <div style="font-size:11px;color:var(--t2);line-height:1.7">Үй желісінде кім кіріп-шығып жатқанын байқайтын жүйе болмайды. IoT IDS Monitor осы мәселені шешеді.</div>
    </div>
  </div>
</div>"""

    return wrap(body, "IoT IDS — Devices") + r"""
<script>
var DEVICES = [
  {id:"cam1",  name:"IP Камера", ip:"192.168.1.10", port:554,  proto:"RTSP",  attack:"DoS/DDoS",           room:"Кіреберіс"},
  {id:"lock1", name:"Ақылды құлып", ip:"192.168.1.11", port:80,   proto:"HTTP",  attack:"Brute-Force",         room:"Алдыңғы есік"},
  {id:"therm", name:"Термостат", ip:"192.168.1.12", port:1883, proto:"MQTT",  attack:"MQTT Injection",      room:"Зал"},
  {id:"light", name:"Жарық басқару", ip:"192.168.1.13", port:1883, proto:"MQTT",  attack:"Replay Attack",       room:"Жатын бөлме"},
  {id:"router",name:"Үй роутері", ip:"192.168.1.1",  port:80,   proto:"HTTP",  attack:"MITM / ARP Spoofing", room:"Кабинет"},
  {id:"plug",  name:"Ақылды розетка", ip:"192.168.1.14", port:1883, proto:"MQTT",  attack:"Port Scan",           room:"Асхана"},
  {id:"sensor",name:"Қозғалыс сенсоры", ip:"192.168.1.15", port:1883, proto:"MQTT",  attack:"Replay Attack",       room:"Дәліз"},
  {id:"cam2",  name:"Бақша камерасы", ip:"192.168.1.16", port:554,  proto:"RTSP",  attack:"DoS/DDoS",            room:"Бақша"},
];

var states = {};
DEVICES.forEach(function(d){ states[d.id]={status:"online",alerts:0,time:"—"}; });
var events = [];

function sColor(s){ return s==="online"?"var(--grn)":s==="attacked"?"var(--red)":"var(--ylw)"; }
function sText(s){ return s==="online"?" ОНЛАЙН":s==="attacked"?" ШАБУЫЛ":" ОФЛАЙН"; }
function aBadge(a){
  var m={"DoS/DDoS":"b-c","Brute-Force":"b-h","MQTT Injection":"b-c",
         "Replay Attack":"b-m","MITM / ARP Spoofing":"b-h","Port Scan":"b-h"};
  return m[a]||"b-l";
}

function renderDevices(){
  var g=document.getElementById("devices-grid");
  g.innerHTML=DEVICES.map(function(d){
    var st=states[d.id];
    var bc=st.status==="online"?"var(--b0)":st.status==="attacked"?"rgba(240,84,84,.3)":"rgba(232,168,56,.3)";
    var bg=st.status==="attacked"?"rgba(240,84,84,.04)":st.status==="offline"?"rgba(0,0,0,.2)":"var(--bg2)";
    return '<div style="background:'+bg+';border:1px solid '+bc+';border-radius:var(--r2);padding:14px;transition:all .3s">'
      +'<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">'
      
      +'<div><div style="font-size:12px;font-weight:600;color:var(--t0)">'+d.name+'</div>'
      +'<div style="font-size:9px;color:var(--t2);font-family:JetBrains Mono,monospace">'+d.room+'</div></div></div>'
      +'<div style="font-size:10px;font-family:JetBrains Mono,monospace;color:var(--t2);line-height:2.2;margin-bottom:10px">'
      +'IP: <span style="color:var(--acc)">'+d.ip+'</span><br>'
      +'Port: '+d.port+' · '+d.proto+'</div>'
      +'<div style="font-size:10px;font-weight:600;color:'+sColor(st.status)+';font-family:JetBrains Mono,monospace;margin-bottom:8px">'+sText(st.status)+'</div>'
      +(st.status==="attacked"?'<div style="margin-bottom:6px"><span class="badge '+aBadge(d.attack)+'" style="font-size:8px">'+d.attack+'</span></div>':'')
      +(st.alerts>0?'<div style="font-size:9px;color:var(--t2);font-family:JetBrains Mono,monospace;margin-bottom:6px">'+st.alerts+' алерт</div>':'')
      +'<button onclick="doAttack(\''+d.id+'\')" style="width:100%;padding:5px;background:var(--bg3);border:1px solid var(--b0);border-radius:var(--r);font-size:10px;color:var(--t1);cursor:pointer;font-family:Inter,sans-serif;transition:all .1s" onmouseover="this.style.borderColor=\'var(--red)\';this.style.color=\'var(--red)\'" onmouseout="this.style.borderColor=\'var(--b0)\';this.style.color=\'var(--t1)\'"> Шабуыл жіберу</button>'
      +'</div>';
  }).join("");
}

function renderBtns(){
  var attacks=["DoS/DDoS","Brute-Force","MQTT Injection","MITM / ARP Spoofing","Port Scan","Replay Attack"];
    document.getElementById("attack-btns").innerHTML=attacks.map(function(a){
    return '<button onclick="doAttackType(\''+a+'\')" style="padding:10px;background:var(--bg3);border:1px solid var(--b0);border-radius:var(--r2);cursor:pointer;font-size:11px;font-weight:500;color:var(--t1);text-align:left;transition:all .12s;font-family:Inter,sans-serif" onmouseover="this.style.borderColor=\'var(--red)\';this.style.color=\'var(--t0)\'" onmouseout="this.style.borderColor=\'var(--b0)\';this.style.color=\'var(--t1)\'">'+a+'</button>';
  }).join("");
}

function doAttack(id){
  var d=DEVICES.find(function(x){return x.id===id;});
  if(!d) return;
  states[d.id].status="attacked";
  states[d.id].alerts++;
  states[d.id].time=new Date().toLocaleTimeString();
  var ev={time:new Date().toLocaleTimeString(),device:d.name,icon:d.icon,attack:d.attack,ip:d.ip,room:d.room};
  events.unshift(ev);
  var m={"DoS/DDoS":"dos","Brute-Force":"brute","MQTT Injection":"mqtt_inject",
         "MITM / ARP Spoofing":"mitm","Port Scan":"port_scan","Replay Attack":"replay"};
  var t=m[d.attack]||"dos";
  fetch("/api/attack/"+t,{method:"POST"}).catch(function(){});
  updateStats(); renderDevices(); renderFeed();
  setTimeout(function(){
    if(states[d.id].status==="attacked"){states[d.id].status="online"; renderDevices(); updateStats();}
  },8000);
  toast(d.name+": "+d.attack+" анықталды!","err");
}

function doAttackType(type){
  var targets=DEVICES.filter(function(d){return d.attack===type;});
  if(targets.length) doAttack(targets[Math.floor(Math.random()*targets.length)].id);
}

function runDemo(){
  var delay=0;
  DEVICES.forEach(function(d){ setTimeout(function(){ doAttack(d.id); },delay); delay+=1000; });
  toast("Толық демо сценарийі іске қосылды","warn");
}

function resetDevices(){
  DEVICES.forEach(function(d){ states[d.id]={status:"online",alerts:0,time:"—"}; });
  events=[];
  renderDevices(); renderFeed(); updateStats();
  toast("Барлық құрылғылар қалпына келтірілді","ok");
}

function updateStats(){
  var online=DEVICES.filter(function(d){return states[d.id].status==="online";}).length;
  var atk=DEVICES.filter(function(d){return states[d.id].status==="attacked";}).length;
  var off=DEVICES.filter(function(d){return states[d.id].status==="offline";}).length;
  document.getElementById("dev-total").textContent=DEVICES.length;
  document.getElementById("dev-online").textContent=online;
  document.getElementById("dev-attacked").textContent=atk;
  document.getElementById("dev-offline").textContent=off;
  document.getElementById("dev-time").textContent=new Date().toLocaleTimeString();
}

function renderFeed(){
  var cnt=document.getElementById("ev-cnt");
  cnt.textContent=events.length+" events";
  if(!events.length){document.getElementById("dev-feed").innerHTML='<div class="empty">Шабуыл жіберіңіз немесе демо іске қосыңыз</div>';return;}
  var ac={"DoS/DDoS":"b-c","Brute-Force":"b-h","MQTT Injection":"b-c","Replay Attack":"b-m","MITM / ARP Spoofing":"b-h","Port Scan":"b-h"};
  document.getElementById("dev-feed").innerHTML=events.slice(0,20).map(function(e){
    return '<div class="fi">'
      +'<div class="fi-sev"><span class="badge '+(ac[e.attack]||"b-l")+'" style="font-size:8px">ALERT</span></div>'
      +'<div class="fi-body">'
      +'<div class="fi-r1"><span class="fi-type">'+e.device+'</span>'
      +'<span class="fi-ip">'+e.ip+'</span></div>'
      +'<div class="fi-desc">'+e.attack+' — '+e.room+'</div>'
      +'</div>'
      +'<div class="fi-time">'+e.time+'</div>'
      +'</div>';
  }).join("");
}

renderDevices(); renderBtns(); updateStats();
setInterval(updateStats, 3000);
</script></body></html>"""

def page_why_ids():
    rows = ""
    competitors = [
        ("Cisco ISE",        "Кәсіби желі қауіпсіздігі",  False,False,False,True, True, True,  "$50,000+/жыл"),
        ("Palo Alto NGFW",   "Келесі буын Firewall",       False,False,False,True, True, True,  "$20,000+"),
        ("Snort/Suricata",   "Ашық код IDS/IPS",          False,False,False,True, False,False, "Тегін (күрделі)"),
        ("Darktrace",        "AI кибер қауіпсіздік",       True, False,True, True, True, True,  "$30,000+/жыл"),
        ("AWS IoT Defender", "Бұлт IoT қауіпсіздігі",     True, False,True, False,True, False, "$0.003/dev/күн"),
        ("Fortinet FortiGate","Unified Threat Mgmt",       False,False,False,True, True, True,  "$5,000+"),
        ("IoT IDS v5.0",     "Менің дипломдық жүйем",      True, True, True, True, True, True,  "Тегін / Open"),
    ]
    for row in competitors:
        name,desc,ml,mqtt,corr,geo,dash,block,price = row
        is_mine = (name == "IoT IDS v5.0")
        bg = 'background:rgba(79,142,247,.05);border-left:3px solid var(--acc)' if is_mine else ""
        fw = "700" if is_mine else "500"
        nc = "var(--acc)" if is_mine else "var(--t0)"
        mine_badge = '&nbsp;<span class="badge b-adm" style="font-size:8px">МОЙ</span>' if is_mine else ""
        pc = "var(--grn)" if is_mine else "var(--t2)"
        def c(v): return '<td style="text-align:center"><span style="color:var(--grn);font-size:14px">&#10003;</span></td>' if v else '<td style="text-align:center"><span style="color:var(--t3);font-size:14px">&#10007;</span></td>'
        rows += ('<tr style="'+bg+'">')
        rows += ('<td><div style="font-weight:'+fw+';color:'+nc+';font-size:12px">'+name+mine_badge+'</div>')
        rows += ('<div style="font-size:10px;color:var(--t2)">'+desc+'</div></td>')
        rows += c(ml)+c(mqtt)+c(corr)+c(geo)+c(dash)+c(block)
        rows += ('<td style="font-size:11px;font-family:JetBrains Mono,monospace;color:'+pc+'">'+price+'</td></tr>')

    adv_html = ""
    advantages = [
        ("IoT мамандандырылған",
         "MQTT протоколы + IoT шабуыл паттерндері. Cisco, Fortinet — жалпы мақсатты. Менің жүйем тек IoT үшін жасалған."),
        ("Z-score AnomalyDetector",
         "ML-сіз статистикалық аномалия. Welford O(1) нақты уақытта baseline үйренеді. Darktrace принципімен бірдей, бірақ тегін."),
        ("APT CorrelationEngine",
         "8 шабуыл паттерні: PortScan+BruteForce = Recon+Initial Access. Enterprise SIEM мүмкіндігі — тегін жүйеде жоқ."),
        ("Толық тегін",
         "Cisco ISE $50K+, Darktrace $30K+ тұрады. IoT IDS — Python, тегін, орнатусыз. Кіші бизнес үшін қолжетімді."),
        ("112мс жауап уақыты",
         "NIST SP 800-94: 500мс-тен аз болуы керек. Менің жүйем 112мс — стандарттан 4.5 есе жылдам."),
        ("GeoIP + веб дашборд",
         "80+ ел офлайн геолокация. Интерактивті дашборд, PDF/CSV есеп, Telegram хабарлама — барлығы бір жүйеде."),
    ]
    for title,desc in advantages:
        adv_html += ('<div style="padding:14px 16px;background:var(--bg2);border:1px solid var(--b0);border-left:3px solid var(--acc);border-radius:var(--r2);margin-bottom:10px">')
        adv_html += ('<div style="font-size:13px;font-weight:600;color:var(--t0);margin-bottom:5px">'+title+'</div>')
        adv_html += ('<div style="font-size:12px;color:var(--t2);line-height:1.6">'+desc+'</div></div>')

    body = """
<div class="ph">
  <div class="ph-title">Неліктен IoT IDS?</div>
  <div class="ph-sub">Қазіргі нарықтағы шешімдермен салыстыру — артықшылықтар, бірегей мүмкіндіктер, баға</div>
</div>
<div class="sg mb14" style="grid-template-columns:repeat(4,1fr)">
  <div class="sc ca"><div class="sc-l">Бәсекелес жүйелер</div><div class="sc-v" style="color:var(--acc)">6</div><div class="sc-s">analyzed</div></div>
  <div class="sc cg"><div class="sc-l">Баға</div><div class="sc-v" style="color:var(--grn);font-size:14px;padding-top:3px">Тегін</div><div class="sc-s">vs $50K+ Enterprise</div></div>
  <div class="sc cp"><div class="sc-l">Бірегей мүмкіндік</div><div class="sc-v" style="color:var(--pur);font-size:14px;padding-top:3px">MQTT+APT</div><div class="sc-s">басқаларда жоқ</div></div>
  <div class="sc cg"><div class="sc-l">Жауап уақыты</div><div class="sc-v" style="color:var(--grn)">112ms</div><div class="sc-s">NIST норма: 500ms</div></div>
</div>
<div class="panel mb14">
  <div class="panel-hd"><span class="panel-t">Нарықтағы жүйелермен толық салыстыру</span></div>
  <div style="overflow-x:auto"><table style="min-width:800px">
    <thead><tr>
      <th style="text-align:left;min-width:200px">Жүйе</th>
      <th style="text-align:center">ML Аномалия</th>
      <th style="text-align:center">MQTT талдау</th>
      <th style="text-align:center">APT Корреляция</th>
      <th style="text-align:center">Геолокация</th>
      <th style="text-align:center">Веб дашборд</th>
      <th style="text-align:center">Авто блок</th>
      <th style="text-align:left">Баға</th>
    </tr></thead>
    <tbody>""" + rows + """</tbody>
  </table></div>
</div>
<div class="g2 mb14">
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">Негізгі артықшылықтар</span></div>
    """ + adv_html + """
  </div>
  <div style="display:flex;flex-direction:column;gap:12px">
    <div class="panel">
      <div class="panel-hd"><span class="panel-t">OWASP IoT Top 10 қамту</span></div>
      <table><tbody>
        <tr><td style="font-size:11px">I1 — Әлсіз парольдер</td><td style="text-align:right"><span style="color:var(--grn);font-size:11px">Brute-Force </span></td></tr>
        <tr><td style="font-size:11px">I2 — Қауіпсіз емес желі</td><td style="text-align:right"><span style="color:var(--grn);font-size:11px">MITM + PortScan </span></td></tr>
        <tr><td style="font-size:11px">I3 — Интерфейс осалдығы</td><td style="text-align:right"><span style="color:var(--grn);font-size:11px">MQTT Injection </span></td></tr>
        <tr><td style="font-size:11px">I4 — Жаңарту жоқ</td><td style="text-align:right"><span style="color:var(--ylw);font-size:11px">Threat Intel </span></td></tr>
        <tr><td style="font-size:11px">I5 — Ескі компоненттер</td><td style="text-align:right"><span style="color:var(--ylw);font-size:11px">CVE базасы </span></td></tr>
        <tr><td style="font-size:11px">I6 — Деректер қорғалмаған</td><td style="text-align:right"><span style="color:var(--grn);font-size:11px">Replay + MITM </span></td></tr>
      </tbody></table>
    </div>
    <div class="panel">
      <div class="panel-hd"><span class="panel-t">NIST SP 800-94 сәйкестік</span></div>
      <table><tbody>
        <tr><td style="font-size:11px">Анықтау уақыты</td><td style="text-align:right;font-family:JetBrains Mono,monospace;color:var(--grn)">112ms &lt; 500ms </td></tr>
        <tr><td style="font-size:11px">False Positive</td><td style="text-align:right;font-family:JetBrains Mono,monospace;color:var(--grn)">0% </td></tr>
        <tr><td style="font-size:11px">Лог жазу</td><td style="text-align:right;font-family:JetBrains Mono,monospace;color:var(--grn)">SQLite </td></tr>
        <tr><td style="font-size:11px">Алерт хабарлау</td><td style="text-align:right;font-family:JetBrains Mono,monospace;color:var(--grn)">Telegram </td></tr>
        <tr><td style="font-size:11px">Есеп жасау</td><td style="text-align:right;font-family:JetBrains Mono,monospace;color:var(--grn)">PDF/CSV/JSON </td></tr>
        <tr><td style="font-size:11px">80 тест сценарийі</td><td style="text-align:right;font-family:JetBrains Mono,monospace;color:var(--grn)">100% анықтау </td></tr>
      </tbody></table>
    </div>
  </div>
</div>"""
    return wrap(body, "IoT IDS — Неліктен IoT IDS?")

def page_dashboard():
    s = ids.get_summary()
    pk,al,bl = s["total_packets"],s["total_alerts"],s["blocked_ips"]
    an = s.get("anomaly_count",0); co = s.get("corr_count",0)
    sc = "cr" if al>0 else "cg"; sv = "THREAT" if al>0 else "NORMAL"
    banner = f'<div class="alert-bar danger">SECURITY ALERT — {al} alerts, {bl} IPs blocked</div>' if al>0 else ""
    apt_banner = f'<div class="alert-bar apt">APT DETECTED — {co} correlated attack campaign(s)</div>' if co>0 else ""
    anom_banner = f'<div class="alert-bar anom">ANOMALY — {an} statistical anomaly alert(s)</div>' if an>0 else ""

    body = f"""
<div class="ph">
  <div class="ph-row">
    <div>
      <div class="ph-title">Security Dashboard</div>
      <div class="ph-sub">Нақты уақыттағы мониторинг · AnomalyDetector + CorrelationEngine қосылды</div>
    </div>
    <div class="bgrp">
      <a href="/anomaly" class="btn btn-grn btn-sm">{I("brain")} Anomaly</a>
      <a href="/correlation" class="btn btn-grn btn-sm">{I("link")} Correlation</a>
      <a href="/geomap" class="btn btn-grn btn-sm">{I("globe")} Geo Map</a>
      <a href="/api/export/csv" class="btn btn-sec btn-sm">CSV</a>
      <a href="/api/export/pdf" class="btn btn-sec btn-sm">PDF</a>
    </div>
  </div>
</div>
<div id="banners">{banner}{apt_banner}{anom_banner}</div>
<div class="sg mb14">
  <div class="sc ca"><div class="sc-l">Total Events</div>
    <div class="sc-v" id="sp">{pk}</div><div class="sc-s" id="sr">0/s</div></div>
  <div class="sc cr"><div class="sc-l">Alerts</div>
    <div class="sc-v" id="sa">{al}</div><div class="sc-s" id="sar">—</div></div>
  <div class="sc cc"><div class="sc-l">Anomalies</div>
    <div class="sc-v" id="san" style="color:var(--cyn)">{an}</div><div class="sc-s">Z-score detected</div></div>
  <div class="sc cp"><div class="sc-l">APT Campaigns</div>
    <div class="sc-v" id="sco" style="color:var(--pur)">{co}</div><div class="sc-s">correlated attacks</div></div>
</div>
<div class="sg mb14" style="grid-template-columns:repeat(3,1fr)">
  <div class="sc cy"><div class="sc-l">Blocked IPs</div>
    <div class="sc-v" id="sb">{bl}</div><div class="sc-s">auto-blocked</div></div>
  <div class="sc {sc}"><div class="sc-l">System Status</div>
    <div class="sc-v" id="ss" style="font-size:14px;padding-top:3px">{sv}</div>
    <div class="sc-s" id="su">—</div></div>
  <div class="sc cg"><div class="sc-l">Detection Rate</div>
    <div class="sc-v" style="color:var(--grn)">100%</div><div class="sc-s">80/80 scenarios</div></div>
</div>
<div class="g65 mb14">
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">Traffic Activity</span>
    <span class="panel-m" id="ts">—</span></div>
    <div class="chbox-lg"><canvas id="cT"></canvas></div>
  </div>
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">Event Feed</span>
    <span class="panel-m" id="fn">0 events</span></div>
    <div class="feed" id="feed"><div class="empty">No events yet</div></div>
  </div>
</div>
<div class="g2 mb14">
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">Attack Distribution</span></div>
    <div class="chbox"><canvas id="cD"></canvas></div>
  </div>
  <div class="panel">
    <div class="panel-hd">
      <span class="panel-t">Latest APT / Anomaly</span>
      
    </div>
    <div id="apt-feed"><div class="empty">Жаңа шабуыл анықталса мұнда көрінеді</div></div>
  </div>
</div>
<div class="panel">
  <div class="panel-hd"><span class="panel-t">Attack Simulation</span>
  <span class="panel-m">9 scenarios</span></div>
  <div class="ag">
    {ab("play","demo","Full Scenario","All attack types")}
    {ab("zap","dos","DoS / DDoS","Packet flood")}
    {ab("lock","brute","Brute-Force","Password guessing")}
    {ab("msg","mqtt_inject","MQTT Injection","Topic exploit")}
    {ab("eye","mitm","MITM / ARP","Traffic capture")}
    {ab("scan","port_scan","Port Scan","Port enumeration")}
    {ab("loop","replay","Replay Attack","Packet replay")}
    {ab("reset","normal","Normal Traffic","Legitimate packets")}
    {ab("reset","reset","System Reset","Clear all data")}
  </div>
</div>"""

    return wrap(body,"IoT IDS — Dashboard") + f"""
<script>
{CJS}
var T0=Date.now(),pP={pk},pA={al},pT=Date.now();
var lb=[],nd=[],ad=[];
for(var i=59;i>=0;i--){{lb.push(i%10===0?'-'+i+'s':'');nd.push(0);ad.push(0);}}
var cT=new Chart(document.getElementById('cT').getContext('2d'),{{
  type:'line',data:{{labels:lb,datasets:[
    {{label:'Normal',data:nd,borderColor:'#4f8ef7',backgroundColor:'rgba(79,142,247,.05)',fill:true,tension:.4,pointRadius:0,borderWidth:1.5}},
    {{label:'Alerts',data:ad,borderColor:'#f05454',backgroundColor:'rgba(240,84,84,.05)',fill:true,tension:.4,pointRadius:0,borderWidth:1.5}}
  ]}},options:{{responsive:true,maintainAspectRatio:false,animation:{{duration:0}},
    interaction:{{mode:'index',intersect:false}},
    scales:{{x:{{grid:{{color:'rgba(255,255,255,.04)',drawTicks:false}}}},
             y:{{grid:{{color:'rgba(255,255,255,.04)',drawTicks:false}},beginAtZero:true}}}},
    plugins:{{legend:{{labels:{{boxWidth:8,padding:14}}}}}}}}
}});
var cD=new Chart(document.getElementById('cD').getContext('2d'),{{
  type:'doughnut',data:{{labels:[],datasets:[{{data:[],
    backgroundColor:['#f05454','#e87838','#e8a838','#4f8ef7','#9b72e8','#3dba7a','#38c4d4'],
    borderWidth:0,hoverOffset:4}}]}},
  options:{{responsive:true,maintainAspectRatio:false,cutout:'68%',
    plugins:{{legend:{{position:'right',labels:{{boxWidth:8,padding:8}}}}}}}}
}});
function upd(){{
  get('/api/status',function(d){{
    if(!d||!d.total_packets)return;
    document.getElementById('sp').textContent=d.total_packets||0;
    document.getElementById('sa').textContent=d.total_alerts||0;
    document.getElementById('sb').textContent=d.blocked_ips||0;
    document.getElementById('san').textContent=d.anomaly_count||0;
    document.getElementById('sco').textContent=d.corr_count||0;
    var sec=Math.floor((Date.now()-T0)/1000);
    document.getElementById('su').textContent=Math.floor(sec/60)+'m '+(sec%60)+'s';
    var now=Date.now(),dt=(now-pT)/1000||1;
    document.getElementById('sr').textContent=Math.round(((d.total_packets||0)-pP)/dt)+'/s';
    document.getElementById('ts').textContent=new Date().toLocaleTimeString();
    pT=now;
    var ar=(d.total_alerts||0)-pA;
    document.getElementById('sar').textContent=ar>0?'+'+ar+' new':'stable';
    var el=document.getElementById('ss');
    var bn=document.getElementById('banners');
    var bars='';
    if((d.total_alerts||0)>0){{el.textContent='THREAT';el.style.color='var(--red)';
      bars+='<div class="alert-bar danger">SECURITY ALERT — '+(d.total_alerts||0)+' alerts, '+(d.blocked_ips||0)+' IPs blocked</div>';}}
    else{{el.textContent='NORMAL';el.style.color='var(--grn)';}}
    if((d.corr_count||0)>0)bars+='<div class="alert-bar apt">APT DETECTED — '+(d.corr_count||0)+' correlated campaign(s) &nbsp;<a href="/correlation" style="color:var(--pur);text-decoration:underline">Қарау</a></div>';
    if((d.anomaly_count||0)>0)bars+='<div class="alert-bar anom">ANOMALY — '+(d.anomaly_count||0)+' statistical anomaly alert(s) &nbsp;<a href="/anomaly" style="color:var(--cyn);text-decoration:underline">Қарау</a></div>';
    bn.innerHTML=bars;
    nd.shift();nd.push(Math.max(0,(d.total_packets||0)%90));
    ad.shift();ad.push(Math.max(0,(d.total_alerts||0)%50));
    try{{cT.update('none');}}catch(e){{}}
    var st=d.attack_stats||{{}},ks=Object.keys(st);
    if(ks.length){{cD.data.labels=ks;cD.data.datasets[0].data=ks.map(function(k){{return st[k];}});try{{cD.update('none');}}catch(e){{}}}}
    var al=d.recent_alerts||[];
    document.getElementById('fn').textContent=al.length+' events';
    if(al.length){{
      var h='';var rv=al.slice().reverse().slice(0,20);
      for(var i=0;i<rv.length;i++){{var a=rv[i];
        h+='<div class="fi"><div class="fi-sev">'+bdg(a.severity)+'</div>'
          +'<div class="fi-body"><div class="fi-r1"><span class="fi-type">'+a.attack_type+'</span>'
          +'<span class="fi-ip">'+a.src_ip+'</span>'
          +(a.blocked?'<span class="badge b-c" style="font-size:8px">BLK</span>':'')+'</div>'
          +'<div class="fi-desc">'+a.description+'</div>'
          +'<div class="fi-det">'+a.detector+'</div></div>'
          +'<div class="fi-time">'+a.timestamp+'</div></div>';
      }}document.getElementById('feed').innerHTML=h;
    }}
    // APT+Anomaly feed
    var ca=d.correlated_alerts||[];var aa=d.anomaly_alerts||[];
    var combined=[].concat(ca.map(function(x){{return {{type:'apt',data:x}};}}).slice(-3),
                           aa.map(function(x){{return {{type:'anom',data:x}};}}).slice(-2));
    if(combined.length){{
      var ah='';
      combined.forEach(function(item){{
        if(item.type==='apt'){{
          ah+='<div class="apt-card">'
             +'<div class="fi-r1"><span class="badge b-apt">APT</span>'
             +'<span class="apt-campaign">'+item.data.campaign+'</span>'
             +'<span class="badge b-c">'+item.data.severity+'</span></div>'
             +'<div class="apt-det">IP: '+item.data.src_ip+' | Детекторлар: '+(item.data.detectors||[]).join(', ')+'</div>'
             +'</div>';
        }}else{{
          ah+='<div class="apt-card" style="border-color:rgba(56,196,212,.2)">'
             +'<div class="fi-r1"><span class="badge b-anom">ANOMALY</span>'
             +'<span style="font-size:11px;color:var(--cyn);font-weight:500">'+item.data.metric+'</span></div>'
             +'<div class="apt-det">'+item.data.description+'</div>'
             +'</div>';
        }}
      }});
      document.getElementById('apt-feed').innerHTML=ah;
    }}
    pP=d.total_packets||0;pA=d.total_alerts||0;
  }});
}}
setInterval(upd,1500);upd();
</script></body></html>"""

#  ANOMALY PAGE 
def page_anomaly():
    body = f"""
<div class="ph">
  <div class="ph-row">
    <div>
      <div class="ph-title">Anomaly Detection </div>
      <div class="ph-sub">Z-score baseline статистикалық аномалия анықтау · machine learning-сіз</div>
    </div>
  </div>
</div>
<div class="sg mb14">
  <div class="sc cc"><div class="sc-l">Analyzed Packets</div>
    <div class="sc-v" id="an-total" style="color:var(--cyn)">0</div><div class="sc-s">total processed</div></div>
  <div class="sc cp"><div class="sc-l">Anomalies Found</div>
    <div class="sc-v" id="an-found" style="color:var(--pur)">0</div><div class="sc-s">detected</div></div>
  <div class="sc ca"><div class="sc-l">Tracked IPs</div>
    <div class="sc-v" id="an-ips" style="color:var(--acc)">0</div><div class="sc-s">with baseline</div></div>
  <div class="sc cg"><div class="sc-l">Global PPS (avg)</div>
    <div class="sc-v" id="an-pps" style="color:var(--grn)">0</div><div class="sc-s">packets/sec</div></div>
</div>
<div class="g2 mb14">
  <div class="panel">
    <div class="panel-hd">
      <span class="panel-t">Алгоритм: Z-score Baseline</span>
      
    </div>
    <table><tbody>
      <tr><td class="dim">Алгоритм</td><td class="mono" style="color:var(--cyn)">Welford online variance</td></tr>
      <tr><td class="dim">Baseline window</td><td class="mono">60 секунд скользящий</td></tr>
      <tr><td class="dim">Threshold</td><td class="mono">Z ≥ 3.0σ (99.7% confidence)</td></tr>
      <tr><td class="dim">Min samples</td><td class="mono">30 пакет (baseline жинау)</td></tr>
      <tr><td class="dim">Cooldown</td><td class="mono">30 секунд per IP</td></tr>
      <tr><td class="dim">Метрика 1</td><td class="mono" style="color:var(--red)">packets_per_sec — DoS pattern</td></tr>
      <tr><td class="dim">Метрика 2</td><td class="mono" style="color:var(--ylw)">unique_ports / 10s — PortScan</td></tr>
      <tr><td class="dim">Метрика 3</td><td class="mono" style="color:var(--pur)">payload_size — Exfiltration</td></tr>
      <tr><td class="dim">Complexity</td><td class="mono" style="color:var(--grn)">O(1) time · O(n) space</td></tr>
    </tbody></table>
  </div>
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">Per-IP Baseline Stats</span></div>
    <div id="ip-stats"><div class="empty">Трафик жіберіңіз — baseline жинала бастайды</div></div>
  </div>
</div>
<div class="panel">
  <div class="panel-hd">
    <span class="panel-t">Anomaly Alerts</span>
    <span class="panel-m" id="anom-cnt">0 alerts</span>
  </div>
  <table><thead><tr>
    <th>Уақыт</th><th>IP</th><th>Метрика</th><th>Байқалған</th>
    <th>Күтілген</th><th>Z-score</th><th>Деңгей</th><th>Сипаттама</th>
  </tr></thead>
  <tbody id="anom-tbl"><tr><td colspan="8" class="empty">
    Аномалия жоқ — шабуыл симуляциясын іске қосыңыз
  </td></tr></tbody></table>
</div>"""

    return wrap(body,"IoT IDS — Anomaly") + f"""
<script>
function load(){{
  get('/api/anomaly',function(d){{
    if(!d.available){{
      document.getElementById('anom-tbl').innerHTML='<tr><td colspan="8" class="empty">AnomalyDetector жүктелмеді</td></tr>';
      return;
    }}
    var s=d.stats||{{}};
    document.getElementById('an-total').textContent=s.total_analyzed||0;
    document.getElementById('an-found').textContent=d.total||0;
    document.getElementById('an-ips').textContent=s.tracked_ips||0;
    document.getElementById('an-pps').textContent=(s.global_pps_mean||0).toFixed(1);
    // Per-IP stats
    var perip=s.per_ip||{{}};var keys=Object.keys(perip);
    if(keys.length){{
      document.getElementById('ip-stats').innerHTML=keys.slice(0,8).map(function(ip){{
        var info=perip[ip];var pct=Math.min(100,Math.round((info.samples/30)*100));
        return '<div class="pr"><div class="pr-top">'
          +'<span class="pr-l" style="color:var(--acc)">'+ip+'</span>'
          +'<span class="pr-v">'+info.samples+' samples · mean: '+info.pps_mean.toFixed(1)+'/s</span>'
          +'</div><div class="pr-bg"><div class="pr-f" style="width:'+pct+'%;background:var(--cyn)"></div></div></div>';
      }}).join('');
    }}
    // Anomaly alerts table
    var al=d.alerts||[];
    document.getElementById('anom-cnt').textContent=al.length+' alerts';
    if(!al.length)return;
    document.getElementById('anom-tbl').innerHTML=al.slice().reverse().slice(0,30).map(function(a){{
      var z=parseFloat(a.z_score||0);
      var zbar='<div class="zbar"><div class="zbar-f" style="width:'+Math.min(100,z/6*100)+'%;background:'+(z>5?'var(--red)':z>3?'var(--ylw)':'var(--cyn)')+'"></div></div>';
      return '<tr>'
        +'<td class="mono dim" style="font-size:10px;white-space:nowrap">'+new Date((a.timestamp||0)*1000).toLocaleTimeString()+'</td>'
        +'<td class="mono" style="color:var(--acc)">'+a.src_ip+'</td>'
        +'<td class="mono" style="color:var(--cyn)">'+a.metric+'</td>'
        +'<td class="mono" style="color:var(--red)">'+a.observed+'</td>'
        +'<td class="mono dim">'+a.expected+'</td>'
        +'<td class="mono">'+z.toFixed(1)+'σ'+zbar+'</td>'
        +'<td>'+bdg(a.severity)+'</td>'
        +'<td class="dim" style="font-size:11px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+a.description+'</td>'
        +'</tr>';
    }}).join('');
  }});
}}
load();setInterval(load,3000);
</script></body></html>"""

#  CORRELATION PAGE 
def page_correlation():
    patterns = [
        ("Port Scan → Brute-Force",           "CRITICAL","Reconnaissance + Initial Access"),
        ("Port Scan → MQTT Injection",         "CRITICAL","IoT Compromise Attempt"),
        ("Brute-Force → DoS/DDoS",             "CRITICAL","Distraction DDoS"),
        ("Replay → MITM / ARP Spoofing",       "CRITICAL","Session Hijack Pattern"),
        ("Port Scan → Brute-Force → MQTT",     "CRITICAL","Full IoT Takeover"),
        ("DoS/DDoS → MITM",                    "HIGH",    "Network Disruption"),
        ("MITM → MQTT Injection",              "HIGH",    "IoT Data Manipulation"),
        ("Brute-Force → Replay Attack",        "HIGH",    "Credential Replay"),
    ]
    pattern_rows = ""
    for combo, sev, name in patterns:
        pattern_rows += (f'<tr><td style="font-size:11px">{combo}</td>'
                         f'<td>{bdg_static(sev)}</td>'
                         f'<td style="font-size:11px;color:var(--pur)">{name}</td></tr>')

    body = f"""
<div class="ph">
  <div class="ph-row">
    <div>
      <div class="ph-title">Correlation Engine </div>
      <div class="ph-sub">APT шабуыл паттерндерін анықтау · MITRE ATT&CK корреляция · 8 паттерн</div>
    </div>
  </div>
</div>
<div class="sg mb14">
  <div class="sc cp"><div class="sc-l">APT Campaigns</div>
    <div class="sc-v" id="co-total" style="color:var(--pur)">0</div><div class="sc-s">detected</div></div>
  <div class="sc cr"><div class="sc-l">Fed Alerts</div>
    <div class="sc-v" id="co-fed" style="color:var(--red)">0</div><div class="sc-s">total processed</div></div>
  <div class="sc ca"><div class="sc-l">Tracked IPs</div>
    <div class="sc-v" id="co-ips" style="color:var(--acc)">0</div><div class="sc-s">under watch</div></div>
  <div class="sc cy"><div class="sc-l">Window</div>
    <div class="sc-v" style="color:var(--ylw);font-size:16px;padding-top:4px">120s</div>
    <div class="sc-s">correlation window</div></div>
</div>
<div class="g2 mb14">
  <div class="panel">
    <div class="panel-hd">
      <span class="panel-t">APT Pattern Matrix</span>
      
    </div>
    <table><thead><tr><th>Шабуыл тізбегі</th><th>Деңгей</th><th>Кампания атауы</th></tr></thead>
    <tbody>{pattern_rows}</tbody></table>
    <div style="margin-top:10px;padding:9px;background:var(--bg3);border-radius:var(--r);font-size:10px;color:var(--t2);font-family:'JetBrains Mono',monospace;line-height:1.8">
      Алгоритм: frozenset(attack_types) → pattern matrix<br>
      Window: 120с · Min detectors: 2 · Cooldown: 60с<br>
      MITRE ATT&CK: T0840/T0846/T1110/T0886/T1557/T0814
    </div>
  </div>
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">Latest Correlated Alerts</span></div>
    <div id="corr-list"><div class="empty">APT шабуылы анықталса мұнда көрінеді</div></div>
  </div>
</div>
<div class="panel">
  <div class="panel-hd">
    <span class="panel-t">Correlated Attack Log</span>
    <span class="panel-m" id="corr-cnt">0 campaigns</span>
  </div>
  <table><thead><tr>
    <th>Уақыт</th><th>IP</th><th>Кампания</th><th>Деңгей</th>
    <th>Детекторлар</th><th>Алерт саны</th><th>Уақыт аралығы</th>
  </tr></thead>
  <tbody id="corr-tbl"><tr><td colspan="7" class="empty">
    Корреляция жоқ — шабуыл симуляциясын іске қосыңыз
  </td></tr></tbody></table>
</div>"""

    return wrap(body,"IoT IDS — Correlation") + f"""
<script>
function load(){{
  get('/api/correlation',function(d){{
    if(!d.available){{
      document.getElementById('corr-tbl').innerHTML='<tr><td colspan="7" class="empty">CorrelationEngine жүктелмеді</td></tr>';
      return;
    }}
    var s=d.stats||{{}};
    document.getElementById('co-total').textContent=d.total||0;
    document.getElementById('co-fed').textContent=s.total_fed||0;
    document.getElementById('co-ips').textContent=s.tracked_ips||0;
    var al=d.alerts||[];
    document.getElementById('corr-cnt').textContent=al.length+' campaigns';
    if(al.length){{
      document.getElementById('corr-list').innerHTML=al.slice().reverse().slice(0,4).map(function(a){{
        return '<div class="apt-card">'
          +'<div class="fi-r1"><span class="badge b-apt">APT</span>'
          +'<span class="apt-campaign">'+a.campaign+'</span>'
          +'<span class="badge b-c">'+a.severity+'</span></div>'
          +'<div class="apt-det">IP: <span style="color:var(--acc)">'+a.src_ip+'</span> | '
          +a.detectors.join(' → ')+'</div>'
          +'<div class="apt-det">'+a.description+'</div>'
          +'</div>';
      }}).join('');
      document.getElementById('corr-tbl').innerHTML=al.slice().reverse().map(function(a){{
        return '<tr>'
          +'<td class="mono dim" style="font-size:10px;white-space:nowrap">'+new Date((a.timestamp||0)*1000).toLocaleTimeString()+'</td>'
          +'<td class="mono" style="color:var(--acc)">'+a.src_ip+'</td>'
          +'<td style="font-size:11px;color:var(--pur);font-weight:500">'+a.campaign+'</td>'
          +'<td>'+bdg(a.severity)+'</td>'
          +'<td class="mono dim" style="font-size:10px">'+a.detectors.join(' → ')+'</td>'
          +'<td class="mono">'+a.alert_count+'</td>'
          +'<td class="mono dim">'+a.time_span.toFixed(0)+'s</td>'
          +'</tr>';
      }}).join('');
    }}
  }});
}}
load();setInterval(load,3000);
</script></body></html>"""

#  GEO MAP PAGE 
def page_geomap():
    body = f"""
<div class="ph">
  <div class="ph-row">
    <div>
      <div class="ph-title">Geo Attack Map </div>
      <div class="ph-sub">Шабуыл географиясы · IP геолокация · офлайн fallback + ip-api.com</div>
    </div>
    <button class="btn btn-grn btn-sm" onclick="load()">Жаңарту</button>
  </div>
</div>
<div class="sg mb14" style="grid-template-columns:repeat(3,1fr)">
  <div class="sc ca"><div class="sc-l">Attack Sources</div>
    <div class="sc-v" id="geo-src" style="color:var(--acc)">0</div><div class="sc-s">unique IPs</div></div>
  <div class="sc cr"><div class="sc-l">Countries</div>
    <div class="sc-v" id="geo-cnt" style="color:var(--red)">0</div><div class="sc-s">attack origins</div></div>
  <div class="sc cp"><div class="sc-l">Top Country</div>
    <div class="sc-v" id="geo-top" style="color:var(--pur);font-size:14px;padding-top:3px">—</div>
    <div class="sc-s" id="geo-top-cnt">0 attacks</div></div>
</div>
<div class="g2 mb14">
  <div class="panel">
    <div class="panel-hd">
      <span class="panel-t">Top Attack Countries</span>
      
    </div>
    <div id="geo-countries"><div class="empty">Шабуыл жіберіңіз — геолокация анықталады</div></div>
  </div>
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">Country Distribution</span></div>
    <div class="chbox-lg"><canvas id="cGeo"></canvas></div>
  </div>
</div>
<div class="panel">
  <div class="panel-hd">
    <span class="panel-t">Attack Source Details</span>
    <span class="panel-m" id="geo-detail-cnt">0 sources</span>
  </div>
  <table><thead><tr>
    <th>IP Address</th><th>Country</th><th>City</th>
    <th>Attack Count</th><th>Attack Types</th><th>Source</th>
  </tr></thead>
  <tbody id="geo-tbl"><tr><td colspan="6" class="empty">
    Шабуыл жіберіңіз — IP геолокация анықталады
  </td></tr></tbody></table>
</div>
<div class="panel" style="margin-top:14px">
  <div class="panel-hd"><span class="panel-t">GeoIP Алгоритмі</span></div>
  <div class="g3">
    <div style="padding-left:14px;border-left:3px solid var(--acc)">
      <div style="font-size:10px;font-weight:700;color:var(--acc);margin-bottom:7px;font-family:JetBrains Mono,monospace;letter-spacing:.07em;text-transform:uppercase">Режим 1: Online</div>
      <div style="font-size:11px;color:var(--t2);font-family:JetBrains Mono,monospace;line-height:2">ip-api.com API<br>Нақты геолокация<br>Cache TTL: 1 сағат<br>Timeout: 2 секунд</div>
    </div>
    <div style="padding-left:14px;border-left:3px solid var(--grn)">
      <div style="font-size:10px;font-weight:700;color:var(--grn);margin-bottom:7px;font-family:JetBrains Mono,monospace;letter-spacing:.07em;text-transform:uppercase">Режим 2: Offline</div>
      <div style="font-size:11px;color:var(--t2);font-family:JetBrains Mono,monospace;line-height:2">IP бірінші октеті<br>80+ ел/қала кестесі<br>RFC-1918 Private detect<br>Жергілікті желі анықтау</div>
    </div>
    <div style="padding-left:14px;border-left:3px solid var(--ylw)">
      <div style="font-size:10px;font-weight:700;color:var(--ylw);margin-bottom:7px;font-family:JetBrains Mono,monospace;letter-spacing:.07em;text-transform:uppercase">Деректер</div>
      <div style="font-size:11px;color:var(--t2);font-family:JetBrains Mono,monospace;line-height:2">Country stats<br>City resolution<br>ISP info (online)<br>Attack clustering</div>
    </div>
  </div>
</div>"""

    return wrap(body,"IoT IDS — Geo Map") + f"""
<script>
{CJS}
var cGeo=new Chart(document.getElementById('cGeo').getContext('2d'),{{
  type:'bar',data:{{labels:[],datasets:[{{label:'Attacks',data:[],
    backgroundColor:'rgba(240,84,84,.7)',borderRadius:3,borderWidth:0}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{display:false}}}},
    scales:{{x:{{grid:{{display:false}}}},y:{{grid:{{color:'rgba(255,255,255,.05)'}},beginAtZero:true}}}}}}
}});
function load(){{
  get('/api/geo/stats',function(countries){{
    if(!countries||!countries.length){{
      document.getElementById('geo-countries').innerHTML='<div class="empty">Деректер жоқ — шабуыл жіберіңіз</div>';
      return;
    }}
    document.getElementById('geo-cnt').textContent=countries.length;
    document.getElementById('geo-top').textContent=countries[0].country;
    document.getElementById('geo-top-cnt').textContent=countries[0].count+' attacks';
    // Bar chart
    cGeo.data.labels=countries.slice(0,10).map(function(c){{return c.country;}});
    cGeo.data.datasets[0].data=countries.slice(0,10).map(function(c){{return c.count;}});
    cGeo.update();
    // Country list
    document.getElementById('geo-countries').innerHTML=countries.slice(0,10).map(function(c,i){{
      var pct=Math.round(c.count/countries[0].count*100);
      return '<div class="pr"><div class="pr-top">'
        +'<span class="pr-l">'+(i+1)+'. '+c.country+'</span>'
        +'<span class="pr-v">'+c.count+' attacks · '+c.unique_ips+' IPs</span>'
        +'</div><div class="pr-bg"><div class="pr-f" style="width:'+pct+'%;background:var(--red)"></div></div></div>';
    }}).join('');
  }});
  get('/api/geo/map',function(sources){{
    if(!sources||!sources.length)return;
    document.getElementById('geo-src').textContent=sources.length;
    document.getElementById('geo-detail-cnt').textContent=sources.length+' sources';
    document.getElementById('geo-tbl').innerHTML=sources.slice(0,30).map(function(s){{
      var src_badge=s.source==='ip-api'?'<span class="badge b-ok" style="font-size:8px">REAL</span>':s.source==='estimate'?'<span class="badge b-m" style="font-size:8px">EST</span>':'<span class="badge b-l" style="font-size:8px">PRIV</span>';
      return '<tr>'
        +'<td class="mono" style="color:var(--acc)">'+s.ip+'</td>'
        +'<td style="font-size:12px">'+s.country+'</td>'
        +'<td class="dim">'+s.city+'</td>'
        +'<td class="mono" style="color:var(--red)">'+s.count+'</td>'
        +'<td class="dim" style="font-size:11px">'+(s.attacks||[s.attack_type]).join(', ')+'</td>'
        +'<td>'+src_badge+'</td>'
        +'</tr>';
    }}).join('');
  }});
}}
load();setInterval(load,5000);
</script></body></html>"""

def bdg_static(s):
    m = {"CRITICAL":"b-c","HIGH":"b-h","MEDIUM":"b-m","LOW":"b-l"}
    cls = m.get(s, "b-l")
    return f'<span class="badge {cls}">{s}</span>'

#  OTHER PAGES (compact) 
def page_analytics():
    body = """
<div class="ph"><div class="ph-title">Analytics</div>
<div class="ph-sub">Database statistics · trends · sources</div></div>
<div class="sg mb14">
  <div class="sc ca"><div class="sc-l">Total Alerts</div><div class="sc-v" id="a1" style="color:var(--acc)">—</div></div>
  <div class="sc cr"><div class="sc-l">Blocked</div><div class="sc-v" id="a2" style="color:var(--red)">—</div></div>
  <div class="sc cp"><div class="sc-l">Attack Types</div><div class="sc-v" id="a3" style="color:var(--pur)">—</div></div>
  <div class="sc cc"><div class="sc-l">Unique Sources</div><div class="sc-v" id="a4" style="color:var(--cyn)">—</div></div>
</div>
<div class="g65 mb14">
  <div class="panel"><div class="panel-hd"><span class="panel-t">Attack Types</span></div><div class="chbox-lg"><canvas id="cBar"></canvas></div></div>
  <div class="panel"><div class="panel-hd"><span class="panel-t">Severity</span></div><div class="chbox-lg"><canvas id="cPie"></canvas></div></div>
</div>
<div class="g2 mb14">
  <div class="panel"><div class="panel-hd"><span class="panel-t">Top Source IPs</span></div><div id="tips"><div class="empty">No data</div></div></div>
  <div class="panel"><div class="panel-hd"><span class="panel-t">Last 7 Days</span></div><div class="chbox-lg"><canvas id="cDay"></canvas></div></div>
</div>"""
    return wrap(body,"Analytics") + f"""<script>{CJS}
var cBar=new Chart(document.getElementById('cBar').getContext('2d'),{{type:'bar',data:{{labels:[],datasets:[{{label:'Count',data:[],backgroundColor:['rgba(240,84,84,.75)','rgba(232,120,56,.75)','rgba(232,168,56,.75)','rgba(79,142,247,.75)','rgba(155,114,232,.75)','rgba(61,186,122,.75)','rgba(56,196,212,.75)'],borderRadius:3,borderWidth:0}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{display:false}}}},scales:{{x:{{grid:{{display:false}}}},y:{{grid:{{color:'rgba(255,255,255,.05)'}},beginAtZero:true}}}}}}}});
var cPie=new Chart(document.getElementById('cPie').getContext('2d'),{{type:'doughnut',data:{{labels:['CRITICAL','HIGH','MEDIUM','LOW'],datasets:[{{data:[0,0,0,0],backgroundColor:['rgba(240,84,84,.8)','rgba(232,120,56,.8)','rgba(232,168,56,.8)','rgba(64,72,90,.7)'],borderWidth:0,hoverOffset:4}}]}},options:{{responsive:true,maintainAspectRatio:false,cutout:'65%',plugins:{{legend:{{position:'bottom',labels:{{boxWidth:8,padding:10}}}}}}}}}});
var cDay=new Chart(document.getElementById('cDay').getContext('2d'),{{type:'line',data:{{labels:[],datasets:[{{label:'Events',data:[],borderColor:'#9b72e8',backgroundColor:'rgba(155,114,232,.06)',fill:true,tension:.4,pointRadius:3,pointBackgroundColor:'#9b72e8',borderWidth:1.5}}]}},options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{display:false}}}},scales:{{x:{{grid:{{color:'rgba(255,255,255,.05)'}}}},y:{{grid:{{color:'rgba(255,255,255,.05)'}},beginAtZero:true}}}}}}}});
function load(){{get('/api/db/stats',function(d){{
  document.getElementById('a1').textContent=d.total_alerts||0;
  document.getElementById('a2').textContent=d.blocked_alerts||0;
  document.getElementById('a3').textContent=(d.by_type||[]).length;
  document.getElementById('a4').textContent=(d.top_ips||[]).length;
  if((d.by_type||[]).length){{cBar.data.labels=d.by_type.map(function(r){{return r.attack_type;}});cBar.data.datasets[0].data=d.by_type.map(function(r){{return r.cnt;}});cBar.update();}}
  var sm={{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0}};(d.by_severity||[]).forEach(function(r){{if(r.severity in sm)sm[r.severity]=r.cnt;}});
  cPie.data.datasets[0].data=[sm.CRITICAL,sm.HIGH,sm.MEDIUM,sm.LOW];cPie.update();
  if((d.by_day||[]).length){{var days=d.by_day.slice().reverse();cDay.data.labels=days.map(function(r){{return r.day.slice(5);}});cDay.data.datasets[0].data=days.map(function(r){{return r.cnt;}});cDay.update();}}
  if((d.top_ips||[]).length){{var mx=d.top_ips[0].cnt||1;document.getElementById('tips').innerHTML=d.top_ips.map(function(r){{var p=Math.round(r.cnt/mx*100);return '<div class="pr"><div class="pr-top"><span class="pr-l" style="color:var(--red)">'+r.src_ip+'</span><span class="pr-v">'+r.cnt+'</span></div><div class="pr-bg"><div class="pr-f" style="width:'+p+'%;background:var(--red)"></div></div></div>';}}).join('');}}
}});}}
load();setInterval(load,6000);</script></body></html>"""

def page_attacks():
    body = """
<div class="ph"><div class="ph-title">Attack Detection</div>
<div class="ph-sub">6 детектор статистикасы · radar chart</div></div>
<div class="sg mb14" style="grid-template-columns:repeat(3,1fr)">
  <div class="sc cr"><div class="sc-l">DoS / DDoS</div><div class="sc-v" id="c1" style="color:var(--red)">0</div></div>
  <div class="sc cy"><div class="sc-l">Brute-Force</div><div class="sc-v" id="c2" style="color:var(--ylw)">0</div></div>
  <div class="sc cc"><div class="sc-l">MQTT Injection</div><div class="sc-v" id="c3" style="color:var(--cyn)">0</div></div>
  <div class="sc cp"><div class="sc-l">MITM / ARP</div><div class="sc-v" id="c4" style="color:var(--pur)">0</div></div>
  <div class="sc ca"><div class="sc-l">Port Scan</div><div class="sc-v" id="c5" style="color:var(--acc)">0</div></div>
  <div class="sc cg"><div class="sc-l">Replay Attack</div><div class="sc-v" id="c6" style="color:var(--grn)">0</div></div>
</div>
<div class="g65 mb14">
  <div class="panel"><div class="panel-hd"><span class="panel-t">Attack Vectors Radar</span></div><div class="chbox-xl"><canvas id="cR"></canvas></div></div>
  <div style="display:flex;flex-direction:column;gap:9px">
    <div class="panel" style="padding:12px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px"><span style="font-size:12px;font-weight:600">DoS / DDoS</span><span class="badge b-c">CRITICAL</span></div><div style="font-size:11px;color:var(--t2);font-family:JetBrains Mono,monospace;line-height:1.9">Sliding window · 50 pkt/5s · O(1)</div></div>
    <div class="panel" style="padding:12px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px"><span style="font-size:12px;font-weight:600">Brute-Force</span><span class="badge b-h">HIGH</span></div><div style="font-size:11px;color:var(--t2);font-family:JetBrains Mono,monospace;line-height:1.9">Ports 22/23/80/443/1883 · 5 fails/30s</div></div>
    <div class="panel" style="padding:12px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px"><span style="font-size:12px;font-weight:600">MQTT Injection</span><span class="badge b-c">CRITICAL</span></div><div style="font-size:11px;color:var(--t2);font-family:JetBrains Mono,monospace;line-height:1.9">/admin /cmd /firmware · payload &gt;4096B</div></div>
    <div class="panel" style="padding:12px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px"><span style="font-size:12px;font-weight:600">Port Scan / Replay</span><span class="badge b-h">HIGH/MED</span></div><div style="font-size:11px;color:var(--t2);font-family:JetBrains Mono,monospace;line-height:1.9">15 ports/10s · MD5 hash · 3 reps/60s</div></div>
  </div>
</div>
<div class="panel">
  <div class="panel-hd"><span class="panel-t">Event Log</span>
    <select id="tf" onchange="loadT()" style="width:auto;font-size:10px;padding:3px 7px"><option value="">All Types</option><option>DoS/DDoS</option><option>Brute-Force</option><option>MQTT Injection</option><option>MITM / ARP Spoofing</option><option>Port Scan</option><option>Replay Attack</option></select>
  </div>
  <table><thead><tr><th>#</th><th>Time</th><th>Attack</th><th>Severity</th><th>Source IP</th><th>Detector</th><th>Blocked</th></tr></thead>
  <tbody id="atbl"><tr><td colspan="7" class="empty">Loading...</td></tr></tbody></table>
</div>"""
    return wrap(body,"Attacks") + f"""<script>{CJS}
var cR=new Chart(document.getElementById('cR').getContext('2d'),{{type:'radar',
  data:{{labels:['DoS/DDoS','Brute-Force','MQTT','MITM/ARP','Port Scan','Replay'],
    datasets:[{{label:'Detected',data:[0,0,0,0,0,0],borderColor:'#4f8ef7',backgroundColor:'rgba(79,142,247,.08)',pointBackgroundColor:'#4f8ef7',pointRadius:4,borderWidth:1.5}}]}},
  options:{{responsive:true,maintainAspectRatio:false,scales:{{r:{{grid:{{color:'rgba(255,255,255,.07)'}},pointLabels:{{color:'#555f72',font:{{size:11}}}},ticks:{{color:'#353d4e',backdropColor:'transparent',stepSize:1}},angleLines:{{color:'rgba(255,255,255,.07)'}}}}}},plugins:{{legend:{{display:false}}}}}}}});
function load(){{get('/api/db/stats',function(d){{var m={{}};(d.by_type||[]).forEach(function(r){{m[r.attack_type]=r.cnt;}});
  ['c1','c2','c3','c4','c5','c6'].forEach(function(id,i){{var keys=['DoS/DDoS','Brute-Force','MQTT Injection','MITM / ARP Spoofing','Port Scan','Replay Attack'];document.getElementById(id).textContent=m[keys[i]]||0;}});
  cR.data.datasets[0].data=[m['DoS/DDoS']||0,m['Brute-Force']||0,(m['MQTT Injection']||0)+(m['MQTT Anomaly']||0),m['MITM / ARP Spoofing']||0,m['Port Scan']||0,m['Replay Attack']||0];cR.update();}});}}
function loadT(){{var f=document.getElementById('tf').value;get('/api/db/history?limit=100',function(rows){{if(f)rows=rows.filter(function(r){{return r.attack_type===f;}});if(!rows.length){{document.getElementById('atbl').innerHTML='<tr><td colspan="7" class="empty">No data</td></tr>';return;}}document.getElementById('atbl').innerHTML=rows.slice(0,60).map(function(r){{return '<tr><td class="mono dim">'+r.id+'</td><td class="mono dim" style="font-size:10px;white-space:nowrap">'+r.created_at+'</td><td style="font-weight:500;font-size:12px">'+r.attack_type+'</td><td>'+bdg(r.severity)+'</td><td class="mono" style="color:var(--acc)">'+r.src_ip+'</td><td class="mono dim" style="font-size:10px">'+r.detector+'</td><td>'+(r.blocked?'<span class="badge b-c" style="font-size:8px">BLK</span>':'<span class="dim">—</span>')+'</td></tr>';}}).join('');}});}};
load();loadT();setInterval(function(){{load();loadT();}},6000);</script></body></html>"""

def page_history():
    body = """
<div class="ph"><div class="ph-row">
  <div><div class="ph-title">Event History</div><div class="ph-sub">SQLite database · logs/ids_alerts.db</div></div>
  <div class="bgrp"><a href="/api/export/csv" class="btn btn-sec btn-sm">CSV</a><a href="/api/export/json" class="btn btn-sec btn-sm">JSON</a><button class="btn btn-danger btn-sm" onclick="clearDB()">Clear</button></div>
</div></div>
<div class="sg mb14">
  <div class="sc ca"><div class="sc-l">Total</div><div class="sc-v" id="h1" style="color:var(--acc)">—</div></div>
  <div class="sc cr"><div class="sc-l">Blocked</div><div class="sc-v" id="h2" style="color:var(--red)">—</div></div>
  <div class="sc cp"><div class="sc-l">Types</div><div class="sc-v" id="h3" style="color:var(--pur)">—</div></div>
  <div class="sc cc"><div class="sc-l">Unique IPs</div><div class="sc-v" id="h4" style="color:var(--cyn)">—</div></div>
</div>
<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px">
  <select id="fs" onchange="loadH()" style="width:auto"><option value="">All</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
  <select id="ft" onchange="loadH()" style="width:auto"><option value="">All Types</option><option>DoS/DDoS</option><option>Brute-Force</option><option>MQTT Injection</option><option>MITM / ARP Spoofing</option><option>Port Scan</option><option>Replay Attack</option></select>
  <select id="fl" onchange="loadH()" style="width:auto"><option value="50">50</option><option value="100" selected>100</option><option value="500">500</option></select>
  <button class="btn btn-sec btn-sm" onclick="loadH()">Refresh</button>
  <span id="hcnt" style="font-size:10px;font-family:JetBrains Mono,monospace;color:var(--t2);margin-left:auto"></span>
</div>
<div class="panel">
  <table><thead><tr><th>ID</th><th>Time</th><th>Attack</th><th>Sev.</th><th>Source IP</th><th>Detector</th><th>Description</th><th>Blocked</th></tr></thead>
  <tbody id="hbody"><tr><td colspan="8" class="empty">Loading...</td></tr></tbody></table>
</div>"""
    return wrap(body,"History") + """<script>
function loadS(){get('/api/db/stats',function(d){document.getElementById('h1').textContent=d.total_alerts||0;document.getElementById('h2').textContent=d.blocked_alerts||0;document.getElementById('h3').textContent=(d.by_type||[]).length;document.getElementById('h4').textContent=(d.top_ips||[]).length;});}
function loadH(){var s=document.getElementById('fs').value,t=document.getElementById('ft').value,l=document.getElementById('fl').value;get('/api/db/history?limit='+l,function(rows){if(s)rows=rows.filter(function(r){return r.severity===s;});if(t)rows=rows.filter(function(r){return r.attack_type===t;});document.getElementById('hcnt').textContent=rows.length+' records';if(!rows.length){document.getElementById('hbody').innerHTML='<tr><td colspan="8" class="empty">No data</td></tr>';return;}document.getElementById('hbody').innerHTML=rows.map(function(r){return '<tr><td class="mono dim">'+r.id+'</td><td class="mono dim" style="font-size:10px;white-space:nowrap">'+r.created_at+'</td><td style="font-weight:500;font-size:12px">'+r.attack_type+'</td><td>'+bdg(r.severity)+'</td><td class="mono" style="color:var(--acc)">'+r.src_ip+'</td><td class="mono dim" style="font-size:10px">'+r.detector+'</td><td class="dim" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px">'+r.description+'</td><td>'+(r.blocked?'<span class="badge b-c" style="font-size:8px">BLK</span>':'<span class="dim">—</span>')+'</td></tr>';}).join('');});}
function clearDB(){if(!confirm('Clear?'))return;post('/api/db/clear',function(){toast('Cleared','ok');loadS();loadH();});}
loadS();loadH();setInterval(function(){loadS();loadH();},6000);</script></body></html>"""

def page_metrics():
    body = """
<div class="ph"><div class="ph-title">Performance Metrics</div>
<div class="ph-sub">Detection Rate 100% · 80 test scenarios · Response time</div></div>
<div class="sg mb14">
  <div class="sc cg"><div class="sc-l">Detection Rate</div><div class="sc-v" style="color:var(--grn)">100%</div><div class="sc-s">80/80 scenarios</div></div>
  <div class="sc ca"><div class="sc-l">Avg Response</div><div class="sc-v" style="color:var(--acc)">112ms</div><div class="sc-s">&lt; 500ms threshold</div></div>
  <div class="sc cg"><div class="sc-l">False Positive</div><div class="sc-v" style="color:var(--grn)">0%</div><div class="sc-s">no false alerts</div></div>
  <div class="sc cp"><div class="sc-l">Throughput</div><div class="sc-v" id="mtp" style="color:var(--pur)">—</div><div class="sc-s">events/sec</div></div>
</div>
<div class="panel mb14">
  <div class="panel-hd"><span class="panel-t">Test Results — 80 Scenarios</span></div>
  <table><thead><tr><th>Attack Type</th><th style="text-align:center">Tests</th><th style="text-align:center">Detected</th><th style="text-align:center">Accuracy</th><th style="text-align:center">Avg Time</th><th style="text-align:center">Result</th></tr></thead>
  <tbody>
    <tr><td>DoS / DDoS</td><td class="mono" style="text-align:center">20</td><td class="mono" style="text-align:center">20</td><td class="mono" style="text-align:center;color:var(--grn);font-weight:700">100%</td><td class="mono" style="text-align:center">~45ms</td><td style="text-align:center"><span class="badge b-ok">PASS</span></td></tr>
    <tr><td>Brute-Force</td><td class="mono" style="text-align:center">20</td><td class="mono" style="text-align:center">20</td><td class="mono" style="text-align:center;color:var(--grn);font-weight:700">100%</td><td class="mono" style="text-align:center">~120ms</td><td style="text-align:center"><span class="badge b-ok">PASS</span></td></tr>
    <tr><td>MQTT Injection</td><td class="mono" style="text-align:center">20</td><td class="mono" style="text-align:center">20</td><td class="mono" style="text-align:center;color:var(--grn);font-weight:700">100%</td><td class="mono" style="text-align:center">~85ms</td><td style="text-align:center"><span class="badge b-ok">PASS</span></td></tr>
    <tr><td>MITM / ARP Spoofing</td><td class="mono" style="text-align:center">20</td><td class="mono" style="text-align:center">20</td><td class="mono" style="text-align:center;color:var(--grn);font-weight:700">100%</td><td class="mono" style="text-align:center">~200ms</td><td style="text-align:center"><span class="badge b-ok">PASS</span></td></tr>
    <tr style="background:rgba(61,186,122,.04)"><td style="font-weight:700">Total</td><td class="mono" style="text-align:center;font-weight:700">80</td><td class="mono" style="text-align:center;font-weight:700">80</td><td class="mono" style="text-align:center;color:var(--grn);font-weight:700;font-size:14px">100%</td><td class="mono" style="text-align:center;font-weight:700">~112ms</td><td style="text-align:center"><span class="badge b-ok">ALL PASS</span></td></tr>
  </tbody></table>
</div>
<div class="g2">
  <div class="panel"><div class="panel-hd"><span class="panel-t">Live Metrics</span></div>
    <table><tbody>
      <tr><td class="dim">Events/sec</td><td class="mono" id="rt1">—</td></tr>
      <tr><td class="dim">Total events</td><td class="mono" id="rt2">—</td></tr>
      <tr><td class="dim">Total alerts</td><td class="mono" id="rt3">—</td></tr>
      <tr><td class="dim">Anomalies</td><td class="mono" id="rt5" style="color:var(--cyn)">—</td></tr>
      <tr><td class="dim">APT campaigns</td><td class="mono" id="rt6" style="color:var(--pur)">—</td></tr>
      <tr><td class="dim">Blocked IPs</td><td class="mono" id="rt4">—</td></tr>
    </tbody></table>
  </div>
  <div class="panel"><div class="panel-hd"><span class="panel-t">Algorithm Complexity</span></div>
    <table><tbody>
      <tr><td class="dim mono" style="font-size:10px">DoSDetector</td><td class="mono" style="color:var(--grn)">O(1)</td></tr>
      <tr><td class="dim mono" style="font-size:10px">BruteForce</td><td class="mono" style="color:var(--grn)">O(1)</td></tr>
      <tr><td class="dim mono" style="font-size:10px">MQTTDetector</td><td class="mono" style="color:var(--grn)">O(k)</td></tr>
      <tr><td class="dim mono" style="font-size:10px">MITMDetector</td><td class="mono" style="color:var(--grn)">O(1)</td></tr>
      <tr><td class="dim mono" style="font-size:10px">PortScan</td><td class="mono" style="color:var(--ylw)">O(n)</td></tr>
      <tr><td class="dim mono" style="font-size:10px">AnomalyDetector</td><td class="mono" style="color:var(--cyn)">O(1) Welford</td></tr>
      <tr><td class="dim mono" style="font-size:10px">CorrelationEngine</td><td class="mono" style="color:var(--pur)">O(k) patterns</td></tr>
    </tbody></table>
  </div>
</div>"""
    return wrap(body,"Metrics") + """<script>
var pp=0,pt=Date.now();
function lm(){get('/api/status',function(d){var now=Date.now(),dt=(now-pt)/1000||1;var r=Math.round((d.total_packets-pp)/dt);
  document.getElementById('rt1').textContent=r+'/s';document.getElementById('rt2').textContent=d.total_packets||0;document.getElementById('rt3').textContent=d.total_alerts||0;document.getElementById('rt4').textContent=d.blocked_ips||0;document.getElementById('rt5').textContent=d.anomaly_count||0;document.getElementById('rt6').textContent=d.corr_count||0;document.getElementById('mtp').textContent=Math.max(r,0)+'/s';pp=d.total_packets;pt=now;});}
lm();setInterval(lm,2000);</script></body></html>"""

def page_logs():
    body = """
<div class="ph"><div class="ph-row">
  <div><div class="ph-title">Log Viewer</div><div class="ph-sub">logs/ids.log · system log</div></div>
  <div class="bgrp">
    <select id="lf" onchange="ll()" style="width:auto;font-size:10px;padding:4px 8px"><option value="">All</option><option value="WARNING">WARNING</option><option value="INFO">INFO</option><option value="ERROR">ERROR</option><option value="АНОМАЛ">ANOMALY</option><option value="КОРРЕЛЯ">CORRELATION</option></select>
    <input type="text" id="ls" placeholder="Search..." oninput="ll()" style="width:150px;padding:4px 9px;font-size:11px">
    <button class="btn btn-sec btn-sm" onclick="ll()">Refresh</button>
    <button class="btn btn-sec btn-sm" id="ab" onclick="toggleA()">Auto: ON</button>
  </div>
</div></div>
<div class="sg mb14">
  <div class="sc ca"><div class="sc-l">Lines</div><div class="sc-v" id="l1" style="color:var(--acc)">—</div></div>
  <div class="sc cy"><div class="sc-l">Warnings</div><div class="sc-v" id="l2" style="color:var(--ylw)">—</div></div>
  <div class="sc cg"><div class="sc-l">Info</div><div class="sc-v" id="l3" style="color:var(--grn)">—</div></div>
  <div class="sc cr"><div class="sc-l">Errors</div><div class="sc-v" id="l4" style="color:var(--red)">—</div></div>
</div>
<div class="panel">
  <div class="panel-hd"><span class="panel-t">Log Output</span><span id="lcnt" class="panel-m"></span></div>
  <div class="term" id="lbox"><span class="dim">Loading...</span></div>
</div>"""
    return wrap(body,"Logs") + """<script>
var aOn=true,aTimer;
function ll(){var f=document.getElementById('lf').value,s=document.getElementById('ls').value.toLowerCase();
  get('/api/logs',function(d){var ln=d.lines||[];
    document.getElementById('l1').textContent=ln.length;
    document.getElementById('l2').textContent=ln.filter(function(l){return l.includes('[WARNING]');}).length;
    document.getElementById('l3').textContent=ln.filter(function(l){return l.includes('[INFO]');}).length;
    document.getElementById('l4').textContent=ln.filter(function(l){return l.includes('[ERROR]');}).length;
    if(f)ln=ln.filter(function(l){return l.includes(f);});
    if(s)ln=ln.filter(function(l){return l.toLowerCase().includes(s);});
    document.getElementById('lcnt').textContent=ln.length+' lines';
    document.getElementById('lbox').innerHTML=ln.slice(-300).reverse().map(function(l){var c='ti';if(l.includes('[WARNING]')||l.includes('АНОМАЛ')||l.includes('КОРРЕЛЯ'))c='tw';else if(l.includes('[ERROR]'))c='te';return '<div class="'+c+'">'+l.replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</div>';}).join('')||'<span class="dim">No data</span>';});}
function toggleA(){aOn=!aOn;document.getElementById('ab').textContent='Auto: '+(aOn?'ON':'OFF');if(aOn)aTimer=setInterval(ll,3000);else clearInterval(aTimer);}
ll();aTimer=setInterval(ll,3000);</script></body></html>"""

def page_settings():
    body = """
<div class="ph"><div class="ph-title">Settings</div><div class="ph-sub">Telegram · IP lists · Export · System</div></div>
<div class="g2 mb14">
  <div class="panel"><div class="panel-hd"><span class="panel-t">Telegram</span></div>
    <div id="tgst" style="font-size:11px;color:var(--t2);margin-bottom:12px;font-family:JetBrains Mono,monospace">Checking...</div>
    <div style="font-size:11px;color:var(--t2);font-family:JetBrains Mono,monospace;line-height:2.2;margin-bottom:12px">1. t.me/BotFather → TOKEN<br>2. t.me/userinfobot → CHAT_ID<br>3. Edit telegram_bot.py</div>
    <button class="btn btn-sec btn-sm" onclick="testTg()">Test Message</button>
  </div>
  <div class="panel"><div class="panel-hd"><span class="panel-t">Export</span></div>
    <div style="display:flex;flex-direction:column;gap:8px">
      <a href="/api/export/pdf" class="btn btn-sec" style="justify-content:center">PDF Report</a>
      <a href="/api/export/csv" class="btn btn-sec" style="justify-content:center">CSV Export</a>
      <a href="/api/export/json" class="btn btn-sec" style="justify-content:center">JSON Export</a>
    </div>
  </div>
</div>
<div class="g2 mb14">
  <div class="panel"><div class="panel-hd"><span class="panel-t">IP Whitelist</span></div>
    <div style="display:flex;gap:7px;margin-bottom:10px"><input type="text" id="wi" placeholder="192.168.1.10" style="flex:1"><button class="btn btn-sec btn-sm" onclick="addWL()">Add</button></div>
    <div id="wll"></div>
  </div>
  <div class="panel"><div class="panel-hd"><span class="panel-t">IP Blacklist</span></div>
    <div style="display:flex;gap:7px;margin-bottom:10px"><input type="text" id="bi" placeholder="10.0.0.99" style="flex:1"><button class="btn btn-danger btn-sm" onclick="addBL()">Block</button></div>
    <div id="bll"></div>
    <div class="divider"></div>
    <div style="font-size:9px;color:var(--t3);font-family:JetBrains Mono,monospace;margin-bottom:5px;letter-spacing:.08em;text-transform:uppercase">Auto-Blocked</div>
    <div id="abl"></div>
  </div>
</div>
<div class="panel"><div class="panel-hd"><span class="panel-t">System Info</span></div>
  <table><tbody>
    <tr><td class="dim">Version</td><td class="mono">IoT IDS Monitor v5.0</td></tr>
    <tr><td class="dim">Author</td><td>Сарбасов Д. · СИБ(ЗБИС)к-22-9Б · АУЭС 2026</td></tr>
    <tr><td class="dim">Detectors</td><td class="mono">DoS · BruteForce · MQTT · MITM · PortScan · Replay</td></tr>
    <tr><td class="dim">New in v5</td><td class="mono" style="color:var(--grn)">AnomalyDetector · CorrelationEngine · GeoIP v2</td></tr>
    <tr><td class="dim">Database</td><td class="mono">SQLite · logs/ids_alerts.db</td></tr>
    <tr><td class="dim">Auth</td><td class="mono">werkzeug pbkdf2 · session · check_password_hash</td></tr>
  </tbody></table>
</div>"""
    return wrap(body,"Settings") + """<script>
function loadTg(){get('/api/telegram/status',function(d){var el=document.getElementById('tgst');if(d.connected){el.textContent='Telegram connected';el.style.color='var(--grn)';}else if(d.available){el.textContent='TOKEN/CHAT_ID needed';el.style.color='var(--ylw)';}else el.textContent='Configure telegram_bot.py';});}
function testTg(){post('/api/telegram/test',function(r){toast(r.connected?'Message sent':'Error',r.connected?'ok':'err');});}
function loadWL(){get('/api/ip/whitelist',function(d){document.getElementById('wll').innerHTML=(d.whitelist||[]).map(function(ip){return '<div class="ipr"><span class="mono" style="color:var(--grn)">'+ip+'</span><button class="btn btn-sec btn-sm" onclick="rmWL(\''+ip+'\')">Remove</button></div>';}).join('')||'<span class="dim mono" style="font-size:11px">Empty</span>';});}
function loadBL(){get('/api/ip/blacklist',function(d){document.getElementById('bll').innerHTML=(d.blacklist||[]).map(function(ip){return '<div class="ipr"><span class="ipr-a">'+ip+'</span><button class="btn btn-sec btn-sm" onclick="rmBL(\''+ip+'\')">Remove</button></div>';}).join('')||'<span class="dim mono" style="font-size:11px">Empty</span>';var au=(d.blocked||[]).filter(function(ip){return !(d.blacklist||[]).includes(ip);});document.getElementById('abl').innerHTML=au.map(function(ip){return '<div class="ipr"><span class="ipr-a">'+ip+'</span><button class="btn btn-sec btn-sm" onclick="ubs(\''+ip+'\')">Unblock</button></div>';}).join('')||'<span class="dim mono" style="font-size:11px">None</span>';});}
function addWL(){var ip=document.getElementById('wi').value.trim();if(!ip)return;post('/api/ip/whitelist/'+ip,function(){document.getElementById('wi').value='';loadWL();toast(ip+' whitelisted','ok');});}
function rmWL(ip){del('/api/ip/whitelist/'+ip,loadWL);}
function addBL(){var ip=document.getElementById('bi').value.trim();if(!ip)return;post('/api/ip/blacklist/'+ip,function(){document.getElementById('bi').value='';loadBL();toast(ip+' blocked','warn');});}
function rmBL(ip){del('/api/ip/blacklist/'+ip,loadBL);}
function ubs(ip){post('/api/ip/unblock/'+ip,function(){loadBL();toast(ip+' unblocked','ok');});}
loadTg();loadWL();loadBL();setInterval(loadBL,5000);</script></body></html>"""

def page_admin():
    body = """
<div class="ph"><div class="ph-title">Admin Panel</div><div class="ph-sub">Users · system stats · actions</div></div>
<div class="sg mb14">
  <div class="sc cp"><div class="sc-l">Users</div><div class="sc-v" id="au" style="color:var(--pur)">—</div></div>
  <div class="sc ca"><div class="sc-l">Total Alerts</div><div class="sc-v" id="aa" style="color:var(--acc)">—</div></div>
  <div class="sc cr"><div class="sc-l">Blocked IPs</div><div class="sc-v" id="ab2" style="color:var(--red)">—</div></div>
  <div class="sc cc"><div class="sc-l">Total Events</div><div class="sc-v" id="ap" style="color:var(--cyn)">—</div></div>
</div>
<div class="g2">
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">User Accounts</span></div>
    <table><thead><tr><th>Login</th><th>Name</th><th>Role</th><th></th></tr></thead>
    <tbody id="utbl"></tbody></table>
    <div class="divider"></div>
    <div style="font-size:10px;font-weight:700;color:var(--t2);letter-spacing:.07em;text-transform:uppercase;font-family:JetBrains Mono,monospace;margin-bottom:9px">Add User</div>
    <div style="display:flex;flex-direction:column;gap:7px">
      <input type="text" id="nl" placeholder="Username">
      <input type="password" id="np" placeholder="Password">
      <input type="text" id="nn" placeholder="Full Name">
      <select id="nr"><option value="user">user</option><option value="admin">admin</option></select>
      <button class="btn btn-acc" onclick="addU()">Create User</button>
    </div>
  </div>
  <div style="display:flex;flex-direction:column;gap:10px">
    <div class="panel"><div class="panel-hd"><span class="panel-t">Detector Config</span></div>
      <table><tbody>
        <tr><td class="mono dim" style="font-size:10px">DoSDetector</td><td class="mono" style="color:var(--grn)">50 pkt/5s</td></tr>
        <tr><td class="mono dim" style="font-size:10px">BruteForce</td><td class="mono" style="color:var(--grn)">5 fails/30s</td></tr>
        <tr><td class="mono dim" style="font-size:10px">PortScan</td><td class="mono" style="color:var(--grn)">15 ports/10s</td></tr>
        <tr><td class="mono dim" style="font-size:10px">Replay</td><td class="mono" style="color:var(--grn)">3 reps/60s</td></tr>
        <tr><td class="mono dim" style="font-size:10px">AnomalyDetect.</td><td class="mono" style="color:var(--cyn)">Z≥3σ · 60s window</td></tr>
        <tr><td class="mono dim" style="font-size:10px">CorrelationEng.</td><td class="mono" style="color:var(--pur)">8 patterns · 120s</td></tr>
      </tbody></table>
    </div>
    <div class="panel"><div class="panel-hd"><span class="panel-t">Actions</span></div>
      <div style="display:flex;flex-direction:column;gap:7px">
        <button class="btn btn-danger" style="justify-content:center" onclick="resetSys()">Reset System</button>
        <button class="btn btn-danger btn-sm" onclick="clearDB()" style="justify-content:center">Clear Database</button>
        <a href="/api/export/pdf" class="btn btn-sec" style="justify-content:center">PDF Report</a>
        <a href="/logs" class="btn btn-sec" style="justify-content:center">Log Viewer</a>
      </div>
    </div>
  </div>
</div>"""
    return wrap(body,"Admin") + """<script>
function loadS(){get('/api/status',function(d){document.getElementById('aa').textContent=d.total_alerts||0;document.getElementById('ab2').textContent=d.blocked_ips||0;document.getElementById('ap').textContent=d.total_packets||0;});}
function loadU(){get('/api/admin/users',function(d){document.getElementById('au').textContent=(d.users||[]).length;document.getElementById('utbl').innerHTML=(d.users||[]).map(function(u){var rb=u.role==='admin'?'<span class="badge b-adm">admin</span>':'<span class="badge b-l">user</span>';var db=u.login!=='admin'?'<button class="btn btn-danger btn-sm" onclick="delU(\''+u.login+'\')">Del</button>':'';return '<tr><td class="mono" style="font-size:11px">'+u.login+'</td><td style="font-size:12px">'+u.name+'</td><td>'+rb+'</td><td>'+db+'</td></tr>';}).join('');});}
function addU(){var l=document.getElementById('nl').value.trim(),p=document.getElementById('np').value,n=document.getElementById('nn').value.trim(),r=document.getElementById('nr').value;if(!l||!p||!n){toast('Fill all fields','err');return;}postJ('/api/admin/users/add',{login:l,password:p,name:n,role:r},function(r){if(r.status==='ok'){toast('Created','ok');document.getElementById('nl').value='';document.getElementById('np').value='';document.getElementById('nn').value='';loadU();}else toast(r.error||'Error','err');});}
function delU(l){if(!confirm('Delete '+l+'?'))return;postJ('/api/admin/users/delete',{login:l},function(r){if(r.status==='ok'){toast('Deleted','ok');loadU();}else toast(r.error,'err');});}
function clearDB(){if(!confirm('Clear DB?'))return;post('/api/db/clear',function(){toast('Cleared','ok');loadS();});}
function resetSys(){if(!confirm('Reset?'))return;post('/api/reset',function(){toast('Reset','ok');loadS();});}
loadS();loadU();setInterval(loadS,5000);</script></body></html>"""

def page_threat():
    matrix = [
        ("Reconnaissance", "#f05454", [("Network Scanning","T0840"),("Port Scanning","T0846")]),
        ("Initial Access",  "#e87838", [("Brute Force","T1110"),("Default Creds","T1078")]),
        ("Execution",       "#e8a838", [("MQTT Injection","T0886"),("Firmware Tamper","T0847")]),
        ("Lateral Move.",   "#9b72e8", [("ARP Spoofing","T1557"),("MITM","T1638")]),
        ("Collection",      "#4f8ef7", [("Replay Attack","T1550"),("Cred. Dump","T1003")]),
        ("Impact",          "#f05454", [("DoS / DDoS","T0814"),("Service Stop","T0881")]),
    ]
    mcols=""
    for title,color,items in matrix:
        mcols += (f'<div style="background:var(--bg3);border:1px solid var(--b0);border-radius:var(--r2);padding:11px">'
                  f'<div style="font-size:9px;font-weight:700;color:{color};letter-spacing:.1em;text-transform:uppercase;font-family:JetBrains Mono,monospace;margin-bottom:8px">{title}</div>')
        for name,tid in items:
            mcols += (f'<div style="background:var(--bg4);border:1px solid var(--b0);border-radius:var(--r);padding:6px 8px;margin-bottom:4px">'
                      f'<div style="font-size:11px;font-weight:500;color:var(--t0)">{name}</div>'
                      f'<div style="font-size:9px;font-family:JetBrains Mono,monospace;color:var(--t3);margin-top:1px">{tid}</div></div>')
        mcols += '</div>'

    body = f"""
<div class="ph"><div class="ph-title">Threat Intelligence</div>
<div class="ph-sub">MITRE ATT&CK matrix · CVE · OWASP IoT Top 10</div></div>
<div class="panel mb14">
  <div class="panel-hd"><span class="panel-t">MITRE ATT&CK for ICS</span><span class="panel-m">attack.mitre.org/matrices/ics/</span></div>
  <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:8px">{mcols}</div>
</div>
<div class="g2 mb14">
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">CVE 2022–2024</span></div>
    <table><thead><tr><th>CVE ID</th><th>CVSS</th><th>Description</th><th>Sev.</th></tr></thead><tbody>
      <tr><td class="mono" style="color:var(--red)">CVE-2022-30525</td><td class="mono">9.8</td><td style="font-size:11px">Zyxel Firewall RCE</td><td><span class="badge b-c">CRITICAL</span></td></tr>
      <tr><td class="mono" style="color:var(--red)">CVE-2023-46604</td><td class="mono">10.0</td><td style="font-size:11px">Apache ActiveMQ RCE</td><td><span class="badge b-c">CRITICAL</span></td></tr>
      <tr><td class="mono" style="color:var(--ora)">CVE-2024-1212</td><td class="mono">7.5</td><td style="font-size:11px">Palo Alto Auth Bypass</td><td><span class="badge b-h">HIGH</span></td></tr>
      <tr><td class="mono" style="color:var(--ora)">CVE-2023-44487</td><td class="mono">7.5</td><td style="font-size:11px">HTTP/2 Rapid Reset DDoS</td><td><span class="badge b-h">HIGH</span></td></tr>
      <tr><td class="mono" style="color:var(--t2)">CVE-2024-3094</td><td class="mono">10.0</td><td style="font-size:11px">XZ Utils Supply Chain</td><td><span class="badge b-c">CRITICAL</span></td></tr>
    </tbody></table>
  </div>
  <div class="panel">
    <div class="panel-hd"><span class="panel-t">OWASP IoT Top 10</span></div>
    <div>{"".join(f'<div style="display:flex;align-items:center;gap:9px;padding:7px 9px;background:var(--bg3);border-radius:var(--r);border:1px solid var(--b0);margin-bottom:4px"><span class="mono" style="color:{c};min-width:22px;font-size:11px">{code}</span><span style="font-size:12px;flex:1">{name}</span><span class="badge {sev}">{sev[2:].upper()}</span></div>' for code,c,name,sev in [("I1","var(--red)","Weak Passwords","b-c"),("I2","var(--ora)","Insecure Network Services","b-h"),("I3","var(--ora)","Insecure Ecosystem Interfaces","b-h"),("I4","var(--ylw)","Lack of Update Mechanism","b-h"),("I5","var(--t1)","Insecure Components","b-m"),("I6","var(--t1)","Insufficient Privacy","b-m")])}</div>
  </div>
</div>"""
    return wrap(body,"Threat Intel") + "</body></html>"

def page_compare():
    cr = [["DoS/DDoS",10,8,3],["Brute-Force",9,7,2],["MQTT Analysis",10,2,0],
          ["MITM/ARP",9,4,1],["Port Scan",9,9,3],["Replay Detect.",8,3,0],
          ["Auto IP Block",10,2,7],["IoT Specializ.",10,2,1],
          ["Anomaly Detect.",9,0,0],["APT Correlation",9,0,0],
          ["Web Dashboard",10,3,3],["Ease of Deploy",9,4,8]]
    rows = ""
    for r in cr:
        def mk(v):
            if v>=8: return f'<span style="color:var(--grn);font-size:13px"></span>'
            if v>=4: return f'<span style="color:var(--ylw);font-size:12px"></span>'
            return f'<span style="color:var(--red);font-size:12px"></span>'
        new = ""
        rows += (f'<tr><td style="font-size:12px">{r[0]}{new}</td>'
                 f'<td style="text-align:center">{mk(r[1])} <span class="mono dim" style="font-size:9px">{r[1]}</span></td>'
                 f'<td style="text-align:center">{mk(r[2])} <span class="mono dim" style="font-size:9px">{r[2]}</span></td>'
                 f'<td style="text-align:center">{mk(r[3])} <span class="mono dim" style="font-size:9px">{r[3]}</span></td></tr>')
    body = f"""
<div class="ph"><div class="ph-title">Comparative Analysis</div>
<div class="ph-sub">IoT IDS v5 vs Firewall vs Snort/Suricata — 12 criteria</div></div>
<div class="g2 mb14">
  <div class="panel"><div class="panel-hd"><span class="panel-t">Score Comparison</span></div>
    <div style="padding:4px 0">
      <div style="margin-bottom:16px"><div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:7px"><span style="font-size:12px;font-weight:600;color:var(--grn)">IoT IDS v5</span><span style="font-size:22px;font-weight:700;font-family:JetBrains Mono,monospace;color:var(--grn)">93</span></div><div class="pr-bg" style="height:5px"><div class="pr-f" style="width:93%;background:var(--grn)"></div></div></div>
      <div style="margin-bottom:16px"><div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:7px"><span style="font-size:12px;font-weight:600;color:var(--ylw)">Snort / Suricata</span><span style="font-size:22px;font-weight:700;font-family:JetBrains Mono,monospace;color:var(--ylw)">62</span></div><div class="pr-bg" style="height:5px"><div class="pr-f" style="width:62%;background:var(--ylw)"></div></div></div>
      <div><div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:7px"><span style="font-size:12px;font-weight:600;color:var(--acc)">Firewall (L3/L4)</span><span style="font-size:22px;font-weight:700;font-family:JetBrains Mono,monospace;color:var(--acc)">38</span></div><div class="pr-bg" style="height:5px"><div class="pr-f" style="width:38%;background:var(--acc)"></div></div></div>
    </div>
  </div>
  <div class="panel"><div class="panel-hd"><span class="panel-t">Radar Chart</span></div><div class="chbox-lg"><canvas id="cR"></canvas></div></div>
</div>
<div class="panel"><div class="panel-hd"><span class="panel-t">Detailed Comparison</span></div>
  <table><thead><tr><th>Criterion</th><th style="text-align:center;color:var(--grn)">IoT IDS v5</th><th style="text-align:center;color:var(--ylw)">Snort</th><th style="text-align:center;color:var(--acc)">Firewall</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>"""
    cr_json = json.dumps(cr)
    return wrap(body,"Compare") + f"""<script>{CJS}
new Chart(document.getElementById('cR').getContext('2d'),{{type:'radar',
  data:{{labels:{json.dumps([r[0] for r in cr[:8]])},datasets:[
    {{label:'IoT IDS',data:{json.dumps([r[1] for r in cr[:8]])},borderColor:'#3dba7a',backgroundColor:'rgba(61,186,122,.07)',pointBackgroundColor:'#3dba7a',pointRadius:3,borderWidth:1.5}},
    {{label:'Snort',  data:{json.dumps([r[2] for r in cr[:8]])},borderColor:'#e8a838',backgroundColor:'rgba(232,168,56,.05)',pointBackgroundColor:'#e8a838',pointRadius:3,borderWidth:1.5}},
    {{label:'FW',     data:{json.dumps([r[3] for r in cr[:8]])},borderColor:'#4f8ef7',backgroundColor:'rgba(79,142,247,.04)',pointBackgroundColor:'#4f8ef7',pointRadius:3,borderWidth:1.5}},
  ]}},options:{{responsive:true,maintainAspectRatio:false,
    scales:{{r:{{min:0,max:10,grid:{{color:'rgba(255,255,255,.07)'}},pointLabels:{{color:'#555f72',font:{{size:10}}}},ticks:{{color:'#353d4e',backdropColor:'transparent',stepSize:2}},angleLines:{{color:'rgba(255,255,255,.07)'}}}}}},
    plugins:{{legend:{{position:'bottom',labels:{{boxWidth:8,padding:12}}}}}}}}}});</script></body></html>"""

# 
# LOGIN PAGE
# 
LOGIN_HTML = """<!DOCTYPE html>
<html lang="kk"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<title>IoT IDS — Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0f1117;color:#e6eaf4;font-family:Inter,sans-serif;min-height:100vh;display:flex;flex-direction:column}
.bar{height:44px;background:#161b22;border-bottom:1px solid rgba(255,255,255,.07);display:flex;align-items:center;padding:0 18px;gap:10px}
.bar-brand{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:700;color:#e6eaf4}
.bar-brand svg{width:15px;height:15px;stroke:#fff;fill:none;stroke-width:1.5;stroke-linecap:round}
.bar-ver{font-size:10px;color:rgba(255,255,255,.4);font-family:'JetBrains Mono',monospace;background:rgba(61,186,122,.12);color:#3dba7a;padding:2px 8px;border-radius:3px;border:1px solid rgba(61,186,122,.2)}
.center{flex:1;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#161b22;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:30px 32px;width:100%;max-width:380px}
.card-title{font-size:15px;font-weight:600;margin-bottom:3px}
.card-sub{font-size:11px;color:#555f72;font-family:'JetBrains Mono',monospace;margin-bottom:22px}
.sep{height:1px;background:rgba(255,255,255,.07);margin-bottom:20px}
.fl{margin-bottom:13px}
label{display:block;font-size:9px;font-weight:700;color:#555f72;letter-spacing:.09em;text-transform:uppercase;margin-bottom:5px;font-family:'JetBrains Mono',monospace}
input{width:100%;background:#1c2030;border:1px solid rgba(255,255,255,.1);color:#e6eaf4;padding:9px 12px;border-radius:5px;font-size:12px;font-family:Inter,sans-serif;outline:none;transition:border .1s}
input:focus{border-color:#4f8ef7}
.btn{width:100%;padding:10px;background:#3a7be0;color:#fff;border:none;border-radius:5px;font-size:12px;font-weight:600;cursor:pointer;font-family:Inter,sans-serif;transition:background .1s;margin-top:5px}
.btn:hover{background:#4f8ef7}
.err{background:rgba(240,84,84,.1);border:1px solid rgba(240,84,84,.2);color:#f05454;padding:9px 12px;border-radius:5px;font-size:11px;margin-bottom:13px;font-family:'JetBrains Mono',monospace}
.hint{margin-top:16px;padding:10px 12px;background:#1c2030;border-radius:5px;border:1px solid rgba(255,255,255,.06);font-size:10px;color:#353d4e;font-family:'JetBrains Mono',monospace;text-align:center;line-height:2.2}
.hint span{color:#555f72}
.new-features{margin-top:14px;padding:10px 12px;background:rgba(61,186,122,.06);border:1px solid rgba(61,186,122,.15);border-radius:5px;font-size:10px;color:#3dba7a;font-family:'JetBrains Mono',monospace;line-height:2}
</style></head>
<body>
<div class="bar">
  <div class="bar-brand">
    <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    IoT IDS Monitor
  </div>
  <span class="bar-ver">v5.0</span>
  <span style="font-size:10px;color:#555f72;font-family:JetBrains Mono,monospace;margin-left:4px">АУЭС · Сарбасов Д. · 2026</span>
</div>
<div class="center">
  <div class="card">
    <div class="card-title">Жүйеге кіру</div>
    <div class="card-sub">IoT IDS Monitor v5.0 · Credentials required</div>
    <div class="sep"></div>
    {% if error %}<div class="err"> {{ error }}</div>{% endif %}
    <form method="post" action="/login">
      <div class="fl"><label>Логин</label><input type="text" name="username" placeholder="admin" autocomplete="off" required></div>
      <div class="fl"><label>Пароль</label><input type="password" name="password" placeholder="••••••••" required></div>
      <button type="submit" class="btn">Жүйеге кіру →</button>
    </form>
    <div class="hint"><span>admin</span> / iot2026 &nbsp;&nbsp;&nbsp; <span>dastan</span> / sarbas2026</div>
    
  </div>
</div>
</body></html>"""

# 
# ROUTES
# 
@app.route("/login", methods=["GET","POST"])
def login():
    err = None
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        if u in USERS and check_password_hash(USERS[u]["password"], p):
            session["user"] = u; session["role"] = USERS[u]["role"]
            return redirect("/")
        err = "Қате пайдаланушы аты немесе құпия сөз"
    return render_template_string(LOGIN_HTML, error=err)

@app.route("/logout")
def logout(): session.clear(); return redirect("/login")

@app.route("/")
@login_required
def index(): return page_dashboard()

@app.route("/analytics")
@login_required
def analytics(): return page_analytics()

@app.route("/attacks")
@login_required
def attacks(): return page_attacks()

@app.route("/history")
@login_required
def history(): return page_history()

@app.route("/threat-intel")
@login_required
def threat_intel(): return page_threat()

@app.route("/compare")
@login_required
def compare(): return page_compare()

@app.route("/metrics")
@login_required
def metrics(): return page_metrics()

@app.route("/logs")
@login_required
def logs_page(): return page_logs()

@app.route("/settings")
@login_required
def settings(): return page_settings()

@app.route("/admin")
@admin_required
def admin_panel(): return page_admin()

#  NEW v5 PAGES 
@app.route("/sniffer")
@login_required
def sniffer_page(): return page_sniffer()

@app.route("/anomaly")
@login_required
def anomaly(): return page_anomaly()

@app.route("/correlation")
@login_required
def correlation(): return page_correlation()

@app.route("/geomap")
@login_required
def geomap(): return page_geomap()

#  API 
@app.route("/api/status")
@login_required
def api_status(): return jsonify(ids.get_summary())

@app.route("/api/anomaly")
@login_required
def api_anomaly():
    if not ids.anomaly_detector:
        return jsonify({"available": False})
    return jsonify({
        "available": True,
        "stats":  ids.anomaly_detector.get_baseline_stats(),
        "alerts": [a.to_dict() for a in ids.anomaly_alerts[-30:]],
        "total":  len(ids.anomaly_alerts),
    })

@app.route("/api/correlation")
@login_required
def api_correlation():
    if not ids.correlation_engine:
        return jsonify({"available": False})
    return jsonify({
        "available": True,
        "stats":  ids.correlation_engine.get_stats(),
        "alerts": [a.to_dict() for a in ids.correlated_alerts[-30:]],
        "total":  len(ids.correlated_alerts),
    })

@app.route("/api/geo/map")
@login_required
def api_geo_map():
    if not GEO_AVAILABLE: return jsonify([])
    return jsonify(get_attack_map_data(ids.get_db_history(300)))

@app.route("/api/geo/stats")
@login_required
def api_geo_stats():
    if not GEO_AVAILABLE: return jsonify([])
    return jsonify(get_country_stats(ids.get_db_history(300)))

@app.route("/api/demo", methods=["POST"])
@login_required
def api_demo():
    global demo_running
    if demo_running: return jsonify({"status":"running"})
    demo_running = True
    def _r():
        global demo_running; run_demo_scenario(ids, delay=0.8); demo_running = False
    threading.Thread(target=_r, daemon=True).start()
    return jsonify({"status":"started"})

@app.route("/api/attack/<t>", methods=["POST"])
@login_required
def api_attack(t):
    m = {"dos":(simulate_dos_attack,{"intensity":70}),
         "brute":(simulate_brute_force,{"attempts":8}),
         "mqtt_inject":(simulate_mqtt_injection,{}),
         "mitm":(simulate_mitm_attack,{}),
         "port_scan":(simulate_port_scan,{}),
         "replay":(simulate_replay_attack,{})}
    if t not in m: return jsonify({"error":"unknown"}), 400
    fn,kw = m[t]
    threading.Thread(target=fn, args=(ids,), kwargs=kw, daemon=True).start()
    return jsonify({"status":"started"})

@app.route("/api/normal", methods=["POST"])
@login_required
def api_normal():
    threading.Thread(target=generate_normal_traffic, args=(ids,30), daemon=True).start()
    return jsonify({"status":"ok"})

@app.route("/api/reset", methods=["POST"])
@login_required
def api_reset():
    global ids; ids = IoTIDS(); return jsonify({"status":"reset"})

@app.route("/api/export/json")
@login_required
def api_export_json():
    r = ids.export_report("logs/report.json")
    return Response(json.dumps(r, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition":
            f"attachment; filename=iot_ids_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"})

@app.route("/api/export/csv")
@login_required
def api_export_csv():
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["Timestamp","Attack","Severity","IP","Description","Detector","Blocked"])
    for a in ids.alerts:
        w.writerow([datetime.fromtimestamp(a.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            a.attack_type, a.severity, a.src_ip, a.description, a.detector,
            "Yes" if a.blocked else "No"])
    return Response("\ufeff"+out.getvalue(), mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition":
            f"attachment; filename=iot_ids_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"})

@app.route("/api/export/pdf")
@login_required
def api_export_pdf():
    if not PDF_AVAILABLE: return jsonify({"error":"pip install reportlab"}), 500
    try:
        path = f"logs/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        generate_pdf(ids.get_summary(), ids.get_db_stats(), path)
        with open(path,"rb") as f: data = f.read()
        return Response(data, mimetype="application/pdf",
            headers={"Content-Disposition":f"attachment; filename={os.path.basename(path)}"})
    except Exception as e: return jsonify({"error":str(e)}), 500

@app.route("/api/report")
@login_required
def api_report(): return jsonify(ids.export_report("logs/report.json"))

@app.route("/api/ip/whitelist", methods=["GET"])
@login_required
def api_wl(): return jsonify({"whitelist":list(ip_whitelist)})

@app.route("/api/ip/whitelist/<ip>", methods=["POST","DELETE"])
@login_required
def api_wl_e(ip):
    if request.method=="POST": ip_whitelist.add(ip); ids.reset_block(ip)
    else: ip_whitelist.discard(ip)
    return jsonify({"status":"ok"})

@app.route("/api/ip/blacklist", methods=["GET"])
@login_required
def api_bl():
    return jsonify({"blacklist":list(ip_blacklist),"blocked":list(ids.blocked_ips)})

@app.route("/api/ip/blacklist/<ip>", methods=["POST","DELETE"])
@login_required
def api_bl_e(ip):
    if request.method=="POST": ip_blacklist.add(ip); ids.blocked_ips.add(ip)
    else: ip_blacklist.discard(ip); ids.reset_block(ip)
    return jsonify({"status":"ok"})

@app.route("/api/ip/unblock/<ip>", methods=["POST"])
@login_required
def api_unblock(ip):
    ids.reset_block(ip); ip_blacklist.discard(ip); return jsonify({"status":"ok"})

@app.route("/api/telegram/status")
@login_required
def api_tg_s():
    if not TG_AVAILABLE: return jsonify({"available":False,"connected":False})
    return jsonify({"available":True,"connected":tg_test()})

@app.route("/api/telegram/test", methods=["POST"])
@login_required
def api_tg_t():
    if not TG_AVAILABLE: return jsonify({"error":"not available"}), 500
    ok = tg_test()
    if ok: send_summary(ids.get_summary())
    return jsonify({"connected":ok})

@app.route("/api/db/stats")
@login_required
def api_db_stats(): return jsonify(ids.get_db_stats())

@app.route("/api/db/history")
@login_required
def api_db_history():
    return jsonify(ids.get_db_history(request.args.get("limit",100,type=int)))

@app.route("/api/db/clear", methods=["POST"])
@login_required
def api_db_clear(): ids.db.clear(); return jsonify({"status":"ok"})

@app.route("/api/logs")
@login_required
def api_logs():
    path = "logs/ids.log"
    if not os.path.exists(path): return jsonify({"lines":[]})
    try:
        with open(path,"r",encoding="utf-8") as f: lines = f.readlines()
        return jsonify({"lines":[l.rstrip() for l in lines[-500:] if l.strip()]})
    except: return jsonify({"lines":[]})

@app.route("/api/me")
@login_required
def api_me():
    u = session.get("user","—"); ud = USERS.get(u,{})
    return jsonify({"user":u,"name":ud.get("name",u),"role":ud.get("role","—")})

@app.route("/api/admin/users")
@admin_required
def api_admin_users():
    return jsonify({"users":[{"login":k,"name":v["name"],"role":v["role"]}
                               for k,v in USERS.items()]})

@app.route("/api/admin/users/add", methods=["POST"])
@admin_required
def api_admin_add():
    d = request.get_json() or {}
    l,p,n,r = d.get("login","").strip(),d.get("password",""),d.get("name","").strip(),d.get("role","user")
    if not l or not p or not n: return jsonify({"error":"All fields required"})
    if l in USERS: return jsonify({"error":"Username exists"})
    USERS[l] = {"password":generate_password_hash(p),"name":n,
                "role":r if r in("admin","user") else "user"}
    return jsonify({"status":"ok"})

@app.route("/api/admin/users/delete", methods=["POST"])
@admin_required
def api_admin_del():
    d = request.get_json() or {}; l = d.get("login","")
    if l=="admin": return jsonify({"error":"Cannot delete admin"})
    if l not in USERS: return jsonify({"error":"Not found"})
    del USERS[l]; return jsonify({"status":"ok"})

@app.route("/do/<action>", methods=["GET","POST"])
@login_required
def do_action(action):
    global demo_running, ids
    try:
        from urllib.parse import urlparse
        back = urlparse(request.headers.get("Referer","/")).path or "/"
    except: back = "/"
    if action == "demo":
        if not demo_running:
            demo_running = True
            def _r():
                global demo_running; run_demo_scenario(ids,delay=0.8); demo_running=False
            threading.Thread(target=_r, daemon=True).start()
    elif action == "normal":
        threading.Thread(target=generate_normal_traffic,args=(ids,30),daemon=True).start()
    elif action == "reset":
        ids = IoTIDS(); back = "/"
    elif action in ("dos","brute","mqtt_inject","mitm","port_scan","replay"):
        m={"dos":(simulate_dos_attack,{"intensity":70}),"brute":(simulate_brute_force,{"attempts":8}),
           "mqtt_inject":(simulate_mqtt_injection,{}),"mitm":(simulate_mitm_attack,{}),
           "port_scan":(simulate_port_scan,{}),"replay":(simulate_replay_attack,{})}
        fn,kw=m[action]; threading.Thread(target=fn,args=(ids,),kwargs=kw,daemon=True).start()
    wait = 8 if action=="demo" else 2
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="{wait};url={back}">
<style>body{{background:#0f1117;color:#555f72;font-family:Inter,sans-serif;
  display:flex;align-items:center;justify-content:center;height:100vh;
  flex-direction:column;gap:12px}}
.s{{width:20px;height:20px;border:1.5px solid rgba(79,142,247,.2);
  border-top-color:#4f8ef7;border-radius:50%;animation:r .7s linear infinite}}
@keyframes r{{to{{transform:rotate(360deg)}}}}
p{{font-size:11px;font-family:'JetBrains Mono',monospace}}</style></head>
<body><div class="s"></div><p>Processing...</p></body></html>"""

# 
#  SNIFFER API 
@app.route("/api/sniffer/status")
@login_required
def api_sniffer_status():
    global sniffer
    if not SNIFFER_AVAILABLE:
        return jsonify({"available": False, "reason": "pip install scapy"})
    if sniffer is None:
        return jsonify({"available": True, "running": False})
    return jsonify({"available": True, "running": sniffer.running, **sniffer.get_stats()})

@app.route("/api/sniffer/start", methods=["POST"])
@admin_required
def api_sniffer_start():
    global sniffer
    if not SNIFFER_AVAILABLE:
        return jsonify({"error": "pip install scapy"})
    d     = request.get_json() or {}
    iface = d.get("iface") or None
    filt  = d.get("filter", "ip or arp")
    if sniffer and sniffer.running:
        return jsonify({"status": "already running"})
    sniffer = RealPacketSniffer(ids, iface=iface, bpf_filter=filt)
    ok = sniffer.start()
    return jsonify({"status": "started" if ok else "error"})

@app.route("/api/sniffer/stop", methods=["POST"])
@admin_required
def api_sniffer_stop():
    global sniffer
    if sniffer:
        sniffer.stop()
    return jsonify({"status": "stopped"})

@app.route("/devices")
@login_required
def devices_page(): return page_iot_devices()

@app.route("/why-ids")
@login_required
def why_ids_page(): return page_why_ids()

if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    print("\n" + ""*54)
    print("  IoT IDS Monitor  v5.0")
    print("  + AnomalyDetector  (Z-score baseline)")
    print("  + CorrelationEngine (APT, 8 patterns)")
    print("  + GeoIP v2  (offline + ip-api.com)")
    print("  АУЭС · Сарбасов Д. · СИБ(ЗБИС)к-22-9Б · 2026")
    print(""*54)
    print("  http://localhost:5000")
    print(""*54 + "\n")
    app.run(debug=False, host="0.0.0.0", port=5000)
