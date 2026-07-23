# Analytical Report

## PDF Requirement Mapping

| PDF Requirement | Implementation |
| --- | --- |
| Simulated vulnerable IoT devices | `src/honeypot.py` simulates a medical vitals monitor web panel, Telnet shell, and SSH banner. |
| Default SSH/Telnet credentials and web panels | Telnet and HTTP login attempts are captured with attempted usernames and passwords. |
| Logging of attacker interaction | JSONL events capture IPs, ports, HTTP requests, credentials, commands, uploads, and banners. |
| Keystroke capture | Telnet usernames, passwords, and commands are also stored as line-buffered keystroke transcript events. |
| Uploaded file capture | HTTP `/upload` stores payloads under `logs/uploads/` and records SHA-256 hashes. |
| IOC extraction | `src/analyze_logs.py` extracts attacker IPs, payload hashes, commands, credentials, techniques, and services. |
| Visualization dashboard | `dashboards/index.html` is generated as an offline dashboard with metrics, bars, and origin map. |
| Geolocation analysis | Offline deterministic geolocation enrichment is included for demo use without network dependency. |
| Rollback mechanism | `src/firewall_rules.py rollback <ip>` reverses simulated block rules. |
| Blocked threat visibility | The dashboard reports active block rules, rollback history, and internal alert severity totals. |
| Architectural documentation | `docs/ARCHITECTURE.md` documents flow, ports, and safety boundaries. |

## Key Indicators

The parser extracts these IOCs from `logs/events.jsonl`:

- Attacker source IP addresses.
- Attempted usernames and passwords.
- Shell commands.
- Uploaded payload SHA-256 hashes.
- Targeted service and vulnerability category.

## Operational Workflow

1. Start the honeypot in a controlled lab network.
2. Watch `logs/events.jsonl` and `logs/alerts.jsonl`.
3. Allow the honeypot to auto-block repeated suspicious sources or add a manual block with `src/firewall_rules.py block`.
4. Run `src/analyze_logs.py` to update `logs/iocs.json` and `dashboards/index.html`.
5. If the analyst confirms a false positive, run `src/firewall_rules.py rollback`.

## Limitations

This project is a safe MVP. It does not replace Cowrie or Honeyd for high-fidelity production deception. It provides the core project deliverables in a portable, auditable implementation suitable for demonstration and extension.
