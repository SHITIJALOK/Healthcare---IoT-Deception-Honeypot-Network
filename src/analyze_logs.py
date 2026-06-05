from __future__ import annotations

import html
import ipaddress
from collections import Counter, defaultdict
from pathlib import Path

from common import DASHBOARD_DIR, LOG_DIR, ensure_dirs, iter_jsonl, utc_now, write_json


EVENT_LOG = LOG_DIR / "events.jsonl"
IOC_PATH = LOG_DIR / "iocs.json"
DASHBOARD_PATH = DASHBOARD_DIR / "index.html"


TECHNIQUE_KEYWORDS = {
    "credential_bruteforce": ["login_attempt"],
    "reconnaissance": ["uname", "whoami", "id", "ifconfig", "ip addr", "busybox"],
    "credential_access": ["cat /etc/passwd", "shadow"],
    "payload_staging": ["wget", "curl", "tftp", "payload_upload"],
    "web_exploit_probe": ["../", "etc/passwd", "cmd=", "admin", "cgi-bin"],
}


def classify_country(ip: str) -> tuple[str, str, float, float]:
    """Offline demo geolocation. This is deterministic, not a live GeoIP lookup."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ("Unknown", "Unknown", 0.0, 0.0)
    if address.is_private:
        return ("Internal", "Hospital LAN", 0.0, 0.0)
    first = int(str(address).split(".")[0]) if address.version == 4 else int(address) % 255
    buckets = [
        ("United States", "North America", 39.8, -98.6),
        ("Germany", "Europe", 51.2, 10.4),
        ("India", "Asia", 20.6, 78.9),
        ("Brazil", "South America", -14.2, -51.9),
        ("Singapore", "Asia", 1.35, 103.8),
    ]
    return buckets[first % len(buckets)]


def detect_techniques(event: dict) -> list[str]:
    haystack = " ".join(
        str(event.get(key, ""))
        for key in ("event_type", "command", "path", "payload", "query", "method")
    ).lower()
    matches = []
    for technique, keywords in TECHNIQUE_KEYWORDS.items():
        if any(keyword in haystack for keyword in keywords):
            matches.append(technique)
    return matches or ["unknown"]


def analyze() -> dict:
    ensure_dirs()
    events = list(iter_jsonl(EVENT_LOG))
    ip_counter: Counter[str] = Counter()
    service_counter: Counter[str] = Counter()
    event_counter: Counter[str] = Counter()
    command_counter: Counter[str] = Counter()
    technique_counter: Counter[str] = Counter()
    payload_hashes: set[str] = set()
    by_country: Counter[str] = Counter()
    geo_points = []
    credentials = []

    for event in events:
        source_ip = event.get("source_ip")
        if source_ip:
            ip_counter[source_ip] += 1
            country, region, lat, lon = classify_country(source_ip)
            by_country[country] += 1
            geo_points.append({"ip": source_ip, "country": country, "region": region, "lat": lat, "lon": lon})
        if event.get("service"):
            service_counter[event["service"]] += 1
        if event.get("event_type"):
            event_counter[event["event_type"]] += 1
        if event.get("command"):
            command_counter[event["command"]] += 1
        if event.get("sha256"):
            payload_hashes.add(event["sha256"])
        if event.get("event_type") == "login_attempt":
            credentials.append(
                {
                    "source_ip": source_ip,
                    "service": event.get("service"),
                    "username": event.get("username"),
                    "password": event.get("password"),
                }
            )
        for technique in detect_techniques(event):
            technique_counter[technique] += 1

    iocs = {
        "generated_at": utc_now(),
        "total_events": len(events),
        "attacker_ips": sorted(ip_counter),
        "payload_hashes": sorted(payload_hashes),
        "top_commands": command_counter.most_common(20),
        "credentials_attempted": credentials,
        "techniques": dict(technique_counter),
        "services": dict(service_counter),
        "event_types": dict(event_counter),
        "countries": dict(by_country),
        "geo_points": geo_points,
    }
    write_json(IOC_PATH, iocs)
    DASHBOARD_PATH.write_text(render_dashboard(iocs), encoding="utf-8")
    return iocs


def bar_rows(counter: dict[str, int]) -> str:
    if not counter:
        return "<p>No data yet.</p>"
    max_value = max(counter.values()) or 1
    rows = []
    for key, value in sorted(counter.items(), key=lambda item: item[1], reverse=True):
        pct = int((value / max_value) * 100)
        rows.append(
            f"<div class='bar'><span>{html.escape(str(key))}</span><b style='width:{pct}%'>{value}</b></div>"
        )
    return "\n".join(rows)


def render_dashboard(iocs: dict) -> str:
    ips = "\n".join(f"<li>{html.escape(ip)}</li>" for ip in iocs["attacker_ips"]) or "<li>No attackers yet</li>"
    hashes = "\n".join(f"<li><code>{h}</code></li>" for h in iocs["payload_hashes"]) or "<li>No uploads yet</li>"
    commands = "\n".join(
        f"<li><code>{html.escape(cmd)}</code> <span>{count}</span></li>" for cmd, count in iocs["top_commands"]
    ) or "<li>No shell commands yet</li>"

    points = []
    for point in iocs["geo_points"][:80]:
        x = 50 + (float(point["lon"]) / 180.0) * 45
        y = 50 - (float(point["lat"]) / 90.0) * 35
        points.append(f"<circle cx='{x:.2f}%' cy='{y:.2f}%' r='5'><title>{html.escape(point['ip'])}</title></circle>")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Healthcare IoT Honeypot Threat Dashboard</title>
  <style>
    :root {{ --ink:#102027; --paper:#f6f1e8; --accent:#c2410c; --cool:#0f766e; --muted:#6b7280; }}
    body {{ margin:0; font-family: Georgia, 'Times New Roman', serif; color:var(--ink); background:radial-gradient(circle at top left,#fff7ed,var(--paper) 40%,#dbeafe); }}
    header {{ padding:48px 7vw 28px; border-bottom:4px solid var(--ink); }}
    h1 {{ font-size:clamp(2rem,5vw,4.5rem); line-height:.95; margin:0; max-width:900px; }}
    main {{ padding:32px 7vw 56px; display:grid; gap:24px; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); }}
    section {{ background:rgba(255,255,255,.78); border:2px solid var(--ink); box-shadow:8px 8px 0 rgba(16,32,39,.18); padding:22px; }}
    .metric {{ font-size:3rem; font-weight:700; color:var(--accent); }}
    .wide {{ grid-column:1/-1; }}
    .bar {{ display:grid; grid-template-columns:150px 1fr; gap:12px; align-items:center; margin:10px 0; }}
    .bar b {{ display:block; min-width:26px; padding:5px 8px; color:white; background:var(--cool); }}
    svg {{ width:100%; min-height:320px; background:linear-gradient(135deg,#0f172a,#1e293b); border:2px solid var(--ink); }}
    circle {{ fill:#fb923c; stroke:white; stroke-width:2; opacity:.85; }}
    code {{ background:#111827; color:#fef3c7; padding:2px 5px; border-radius:4px; }}
    ul {{ padding-left:20px; }}
  </style>
</head>
<body>
  <header>
    <p>Generated {html.escape(iocs['generated_at'])}</p>
    <h1>Healthcare IoT Honeypot Threat Dashboard</h1>
  </header>
  <main>
    <section><h2>Total Events</h2><div class="metric">{iocs['total_events']}</div></section>
    <section><h2>Attacker IPs</h2><div class="metric">{len(iocs['attacker_ips'])}</div></section>
    <section><h2>Payload Hashes</h2><div class="metric">{len(iocs['payload_hashes'])}</div></section>
    <section class="wide"><h2>Attack Origin Map</h2><svg viewBox="0 0 100 100" preserveAspectRatio="none"><path d="M5,55 C20,30 35,35 45,48 S68,42 82,57 S95,66 98,45" fill="none" stroke="#94a3b8" stroke-width="10" opacity=".45"/>{''.join(points)}</svg></section>
    <section><h2>Techniques</h2>{bar_rows(iocs['techniques'])}</section>
    <section><h2>Services</h2>{bar_rows(iocs['services'])}</section>
    <section><h2>Countries</h2>{bar_rows(iocs['countries'])}</section>
    <section><h2>Source IPs</h2><ul>{ips}</ul></section>
    <section><h2>Commands</h2><ul>{commands}</ul></section>
    <section><h2>Uploaded Payload Hashes</h2><ul>{hashes}</ul></section>
  </main>
</body>
</html>"""


if __name__ == "__main__":
    summary = analyze()
    print(f"Analyzed {summary['total_events']} events")
    print(f"Wrote {IOC_PATH}")
    print(f"Wrote {DASHBOARD_PATH}")
