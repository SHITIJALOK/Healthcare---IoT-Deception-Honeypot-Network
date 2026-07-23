# Healthcare IoT Deception Honeypot Network

Low-interaction healthcare IoT honeypot that simulates vulnerable medical-device services, captures attacker behavior, extracts indicators of compromise, and renders an offline threat dashboard.

The project is intentionally safe by default:

- Binds to localhost unless configured otherwise.
- Uses high ports instead of privileged production ports.
- Simulates firewall blocking in a JSON state file instead of changing OS firewall rules.
- Stores uploaded payloads in a sandbox directory and records SHA-256 hashes.
- Automatically creates simulated block rules when a source exceeds the configured interaction threshold.

## Components

- `src/honeypot.py` starts simulated HTTP, Telnet, and SSH-banner services.
- `src/analyze_logs.py` parses JSONL events into IOCs, summary metrics, and an HTML dashboard.
- `src/firewall_rules.py` manages simulated block rules with rollback support.
- `src/generate_sample_events.py` creates representative attack traffic for demos.
- `config/device_profile.json` defines the fake medical IoT profile and ports.
- `docs/ARCHITECTURE.md` documents the design and safety boundaries.
- `docs/REPORT.md` maps the implementation to the PDF requirements.

## Quick Start

Use the installed Python interpreter on this machine:

```powershell
& 'C:\Users\shiti\AppData\Local\Programs\Python\Python311\python.exe' src\generate_sample_events.py
& 'C:\Users\shiti\AppData\Local\Programs\Python\Python311\python.exe' src\analyze_logs.py
```

Open `dashboards/index.html` in a browser to view the generated dashboard.

The dashboard includes:

- attack origin map and service distribution
- top attacker IPs and captured commands
- internal alert counts
- active block rules and rollback history

## Run the Honeypot

```powershell
& 'C:\Users\shiti\AppData\Local\Programs\Python\Python311\python.exe' src\honeypot.py
```

Default listeners:

- HTTP medical monitor panel: `127.0.0.1:8080`
- Telnet-like shell trap: `127.0.0.1:2323`
- SSH banner trap: `127.0.0.1:2222`

Generate traffic from another terminal:

```powershell
Invoke-WebRequest http://127.0.0.1:8080/
Invoke-WebRequest http://127.0.0.1:8080/admin?cmd=cat+/etc/passwd
```

Repeated suspicious interactions from the same IP trigger an automatic simulated firewall block based on `config/device_profile.json`.

## Simulated Firewall Workflow

```powershell
& 'C:\Users\shiti\AppData\Local\Programs\Python\Python311\python.exe' src\firewall_rules.py block 203.0.113.45 "brute force against Telnet honeypot"
& 'C:\Users\shiti\AppData\Local\Programs\Python\Python311\python.exe' src\firewall_rules.py list
& 'C:\Users\shiti\AppData\Local\Programs\Python\Python311\python.exe' src\firewall_rules.py rollback 203.0.113.45
```

## Project Notes

The supplied PDF is image-based and has no embedded text layer. Rendered page images are stored in `docs/pdf_pages/` for traceability.
