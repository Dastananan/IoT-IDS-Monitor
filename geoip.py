"""
GeoIP v2 — IP геолокация модулі (офлайн fallback + ip-api.com)
"""
import time, logging, ipaddress
from typing import Optional

logger = logging.getLogger(__name__)

_cache: dict = {}
CACHE_TTL = 3600

_PRIVATE = [
    ("10.0.0.0/8",     "Private", "Local Network", 51.5,  0.1),
    ("172.16.0.0/12",  "Private", "Local Network", 48.9,  2.3),
    ("192.168.0.0/16", "Private", "Local Network", 51.5,  0.1),
    ("127.0.0.0/8",    "Local",   "Loopback",       0.0,  0.0),
]

_OCT1 = {
    1:("Australia","Brisbane",-27.5,153.0),2:("USA","Chicago",41.9,-87.6),
    3:("USA","Los Angeles",34.1,-118.2),4:("USA","Miami",25.8,-80.2),
    5:("Germany","Frankfurt",50.1,8.7),14:("Japan","Tokyo",35.7,139.7),
    27:("South Korea","Seoul",37.6,126.9),31:("Netherlands","Amsterdam",52.4,4.9),
    36:("China","Beijing",39.9,116.4),37:("Russia","Moscow",55.8,37.6),
    41:("South Africa","Cape Town",-33.9,18.4),46:("Sweden","Stockholm",59.3,18.1),
    47:("Norway","Oslo",59.9,10.8),49:("Germany","Berlin",52.5,13.4),
    51:("UK","London",51.5,-0.1),54:("USA","Virginia",37.4,-79.4),
    58:("China","Shanghai",31.2,121.5),60:("Japan","Osaka",34.7,135.5),
    61:("Australia","Sydney",-33.9,151.2),65:("Singapore","Singapore",1.4,103.8),
    66:("USA","Houston",29.8,-95.4),77:("Russia","St.Petersburg",59.9,30.3),
    79:("Russia","Ekaterinburg",56.9,60.6),80:("Poland","Warsaw",52.2,21.0),
    83:("Finland","Helsinki",60.2,25.0),84:("Spain","Madrid",40.4,-3.7),
    85:("Ukraine","Kyiv",50.5,30.5),86:("China","Guangzhou",23.1,113.3),
    87:("Brazil","Sao Paulo",-23.5,-46.6),88:("Italy","Milan",45.5,9.2),
    89:("France","Paris",48.9,2.3),90:("Turkey","Istanbul",41.0,28.9),
    91:("India","Mumbai",19.1,72.9),95:("Russia","Vladivostok",43.1,131.9),
    96:("Kazakhstan","Almaty",43.3,76.9),103:("China","Shenzhen",22.5,114.1),
    104:("USA","New York",40.7,-74.0),114:("China","Wuhan",30.6,114.3),
    121:("Taiwan","Taipei",25.0,121.5),122:("India","Delhi",28.6,77.2),
    123:("India","Bangalore",12.9,77.6),173:("USA","San Francisco",37.8,-122.4),
    185:("Netherlands","Amsterdam",52.4,4.9),188:("Russia","Kazan",55.8,49.1),
    203:("Australia","Perth",-32.0,115.9),204:("USA","Washington",38.9,-77.0),
    206:("Canada","Toronto",43.7,-79.4),212:("Morocco","Casablanca",33.6,-7.6),
    216:("Egypt","Cairo",30.1,31.2),
}

def _private(ip):
    try:
        a = ipaddress.ip_address(ip)
        for cidr,c,ci,la,lo in _PRIVATE:
            if a in ipaddress.ip_network(cidr,strict=False):
                return c,ci,la,lo
    except: pass
    return None

def lookup(ip: str) -> dict:
    if ip in _cache and time.time()-_cache[ip].get("ts",0)<CACHE_TTL:
        return _cache[ip]
    prv = _private(ip)
    if prv:
        c,ci,la,lo = prv
        r = {"country":c,"city":ci,"lat":la,"lon":lo,"source":"private"}
        _cache[ip] = {**r,"ts":time.time()}; return r
    try:
        import urllib.request, json
        data = json.loads(urllib.request.urlopen(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp",timeout=2).read())
        if data.get("status")=="success":
            r = {"country":data.get("country","?"),"city":data.get("city","?"),
                 "lat":data.get("lat",0.0),"lon":data.get("lon",0.0),
                 "isp":data.get("isp",""),"source":"ip-api"}
            _cache[ip]={**r,"ts":time.time()}; return r
    except: pass
    try:
        f = int(ip.split(".")[0])
        if f in _OCT1:
            c,ci,la,lo = _OCT1[f]
            r={"country":c,"city":ci,"lat":la,"lon":lo,"source":"estimate"}
            _cache[ip]={**r,"ts":time.time()}; return r
    except: pass
    r={"country":"Unknown","city":"Unknown","lat":0.0,"lon":0.0,"source":"unknown"}
    _cache[ip]={**r,"ts":time.time()}; return r

def get_geo(ip: str) -> dict:
    """Backwards compat wrapper"""
    g = lookup(ip)
    return {"country":g["country"],"city":g["city"],
            "lat":g["lat"],"lon":g["lon"],"isp":g.get("isp",""),
            "countryCode":g.get("country","?")[:2].upper()}

def _is_private(ip: str) -> bool:
    return _private(ip) is not None

def enrich_alerts(alerts: list) -> list:
    result = []
    for alert in alerts:
        d = dict(alert) if isinstance(alert,dict) else alert.to_dict()
        geo = lookup(d.get("src_ip",""))
        d["geo"] = geo
        result.append(d)
    return result

def get_attack_map_data(alerts: list) -> list:
    seen = {}
    for alert in alerts:
        d = dict(alert) if isinstance(alert,dict) else alert.to_dict()
        ip = d.get("src_ip","")
        if not ip: continue
        geo = lookup(ip)
        if ip not in seen:
            seen[ip] = {"ip":ip,"country":geo["country"],"city":geo["city"],
                        "lat":geo["lat"],"lon":geo["lon"],
                        "source":geo.get("source",""),
                        "attack_type":d.get("attack_type","?"),
                        "severity":d.get("severity","?"),"count":1,"attacks":[d.get("attack_type","?")]}
        else:
            seen[ip]["count"] += 1
            at = d.get("attack_type","?")
            if at not in seen[ip]["attacks"]:
                seen[ip]["attacks"].append(at)
    return [v for v in seen.values() if not(v["lat"]==0 and v["lon"]==0)]

def get_country_stats(alerts: list) -> list:
    cdata = {}
    for a in alerts:
        d = dict(a) if isinstance(a,dict) else a.to_dict()
        geo = lookup(d.get("src_ip",""))
        c = geo["country"]
        if c not in cdata:
            cdata[c] = {"count":0,"attacks":[],"ips":set()}
        cdata[c]["count"] += 1
        cdata[c]["ips"].add(d.get("src_ip",""))
        at = d.get("attack_type","?")
        if at not in cdata[c]["attacks"]:
            cdata[c]["attacks"].append(at)
    return sorted([{"country":k,"count":v["count"],"unique_ips":len(v["ips"]),"attacks":v["attacks"]}
                   for k,v in cdata.items() if k not in ("Unknown","Private","Local")],
                  key=lambda x:-x["count"])
