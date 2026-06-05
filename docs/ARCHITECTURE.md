# Architecture

## Goal

The honeypot simulates a vulnerable healthcare IoT device to detect reconnaissance, brute force attempts, payload staging, and command execution behavior before an attacker reaches real medical equipment.

## Runtime Flow

1. `src/honeypot.py` loads `config/device_profile.json`.
2. Three low-interaction services bind to localhost by default.
3. Every connection, login attempt, command, upload, and probe is appended to `logs/events.jsonl`.
4. Internal source IPs listed in RFC1918 networks also generate `logs/alerts.jsonl`.
5. `src/analyze_logs.py` extracts IOCs and writes `logs/iocs.json`.
6. The same analysis step renders `dashboards/index.html`.
7. `src/firewall_rules.py` lets analysts simulate block rules and roll them back for false positives.

## Simulated Services

| Service | Default Port | Purpose |
| --- | ---: | --- |
| HTTP | 8080 | Fake vitals monitor web panel, login form, admin endpoint, upload endpoint |
| Telnet | 2323 | Fake maintenance shell that captures credentials and commands |
| SSH | 2222 | Banner-grab trap for scanner fingerprinting |

## Safety Boundaries

- The default bind address is `127.0.0.1`.
- The implementation does not execute attacker commands.
- Uploaded data is stored only as sandbox files under `logs/uploads/`.
- Firewall rules are simulated in `config/firewall_rules.json`; no OS firewall is modified.
- The geolocation view is deterministic offline demo enrichment, not a live GeoIP lookup.

## Production Hardening Notes

For a real deployment, place this behind Docker or a VM network with egress disabled, replace the simulated firewall module with an approved SOAR/firewall API integration, and use a real GeoIP database or SIEM enrichment pipeline.
