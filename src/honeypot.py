from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from common import (
    CONFIG_DIR,
    LOG_DIR,
    UPLOAD_DIR,
    append_jsonl,
    ensure_dirs,
    is_internal_ip,
    load_json,
    sha256_bytes,
    utc_now,
)


EVENT_LOG = LOG_DIR / "events.jsonl"
ALERT_LOG = LOG_DIR / "alerts.jsonl"
PROFILE_PATH = CONFIG_DIR / "device_profile.json"


def log_event(event: dict) -> None:
    append_jsonl(EVENT_LOG, event)

    profile = load_json(PROFILE_PATH, {})
    cidrs = profile.get("alerts", {}).get("internal_networks", [])
    source_ip = event.get("source_ip", "")
    if source_ip and is_internal_ip(source_ip, cidrs):
        append_jsonl(
            ALERT_LOG,
            {
                "timestamp": utc_now(),
                "severity": "high",
                "message": "Internal host touched hidden honeypot",
                "source_ip": source_ip,
                "event_type": event.get("event_type"),
                "service": event.get("service"),
            },
        )


def http_response(status: str, body: str, content_type: str = "text/html") -> bytes:
    encoded = body.encode("utf-8")
    headers = [
        f"HTTP/1.1 {status}",
        "Server: MediView-Web/2.1",
        f"Content-Type: {content_type}; charset=utf-8",
        f"Content-Length: {len(encoded)}",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(headers).encode("utf-8") + encoded


def render_panel(profile: dict) -> str:
    device = profile["device"]
    return f"""<!doctype html>
<html>
<head><title>{device['name']} Login</title></head>
<body>
  <h1>{device['name']}</h1>
  <p>Firmware: {device['firmware']} | Serial: {device['serial']} | Location: {device['location']}</p>
  <form method="POST" action="/login">
    <label>User <input name="username"></label><br>
    <label>Password <input name="password" type="password"></label><br>
    <button>Sign in</button>
  </form>
  <p>Diagnostics endpoint: /admin</p>
</body>
</html>"""


async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    source_ip, source_port = peer[0], peer[1]
    profile = load_json(PROFILE_PATH, {})

    try:
        data = await asyncio.wait_for(reader.read(65536), timeout=5)
        request_text = data.decode("utf-8", errors="replace")
        first_line = request_text.splitlines()[0] if request_text else ""
        parts = first_line.split()
        method, target = (parts[0], parts[1]) if len(parts) >= 2 else ("UNKNOWN", "/")
        parsed = urlsplit(target)
        body = request_text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in request_text else ""
        query = parse_qs(parsed.query)

        event = {
            "timestamp": utc_now(),
            "event_type": "network_request",
            "service": "http",
            "source_ip": source_ip,
            "source_port": source_port,
            "method": method,
            "path": parsed.path,
            "query": query,
            "user_agent": extract_header(request_text, "User-Agent"),
        }

        if parsed.path == "/login" and method == "POST":
            fields = parse_qs(body)
            event.update(
                {
                    "event_type": "login_attempt",
                    "username": fields.get("username", [""])[0],
                    "password": fields.get("password", [""])[0],
                    "success": False,
                }
            )
            response = http_response("401 Unauthorized", "<h1>Authentication failed</h1>")
        elif parsed.path == "/upload" and method == "POST":
            digest = sha256_bytes(body.encode("utf-8", errors="replace"))
            upload_path = UPLOAD_DIR / f"{digest}.bin"
            upload_path.write_bytes(body.encode("utf-8", errors="replace"))
            event.update(
                {
                    "event_type": "payload_upload",
                    "sha256": digest,
                    "bytes": upload_path.stat().st_size,
                    "stored_path": str(upload_path.relative_to(LOG_DIR.parent)),
                }
            )
            response = http_response("202 Accepted", "<h1>Firmware package queued</h1>")
        elif parsed.path.startswith("/admin"):
            event.update({"event_type": "exploit_probe", "payload": parsed.query or body})
            response = http_response("403 Forbidden", "<h1>Diagnostics disabled</h1>")
        else:
            response = http_response("200 OK", render_panel(profile))

        log_event(event)
        writer.write(response)
        await writer.drain()
    except Exception as exc:
        log_event(
            {
                "timestamp": utc_now(),
                "event_type": "service_error",
                "service": "http",
                "source_ip": source_ip,
                "error": repr(exc),
            }
        )
    finally:
        writer.close()
        await writer.wait_closed()


def extract_header(request_text: str, header: str) -> str:
    prefix = header.lower() + ":"
    for line in request_text.splitlines():
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""


async def prompt(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, text: str) -> str:
    writer.write(text.encode("utf-8"))
    await writer.drain()
    data = await asyncio.wait_for(reader.readline(), timeout=60)
    return data.decode("utf-8", errors="replace").strip()


async def handle_telnet(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    source_ip, source_port = peer[0], peer[1]
    writer.write(b"MediView VX-240 maintenance console\r\n")
    await writer.drain()

    try:
        username = await prompt(reader, writer, "login: ")
        password = await prompt(reader, writer, "password: ")
        log_event(
            {
                "timestamp": utc_now(),
                "event_type": "login_attempt",
                "service": "telnet",
                "source_ip": source_ip,
                "source_port": source_port,
                "username": username,
                "password": password,
                "success": False,
            }
        )

        writer.write(b"Access denied. Emergency diagnostics shell opened in read-only mode.\r\n")
        await writer.drain()
        for _ in range(20):
            command = await prompt(reader, writer, "mvx240$ ")
            if not command or command.lower() in {"exit", "quit", "logout"}:
                break
            log_event(
                {
                    "timestamp": utc_now(),
                    "event_type": "command",
                    "service": "telnet",
                    "source_ip": source_ip,
                    "command": command,
                }
            )
            writer.write(fake_command_output(command).encode("utf-8"))
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


def fake_command_output(command: str) -> str:
    command_l = command.lower()
    if "uname" in command_l:
        return "Linux mvx240 3.10.14-mediview armv7l GNU/Linux\r\n"
    if "cat /etc/passwd" in command_l:
        return "root:x:0:0:root:/root:/bin/sh\r\nservice:x:100:100:service:/opt/mvx:/bin/sh\r\n"
    if "wget" in command_l or "curl" in command_l:
        return "network: temporary failure in name resolution\r\n"
    if "busybox" in command_l:
        return "BusyBox v1.22.1 (mediview embedded shell)\r\n"
    return "permission denied: read-only diagnostic sandbox\r\n"


async def handle_ssh_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    source_ip, source_port = peer[0], peer[1]
    writer.write(b"SSH-2.0-OpenSSH_6.6.1p1 MediView_Embedded\r\n")
    await writer.drain()
    try:
        client_banner = await asyncio.wait_for(reader.readline(), timeout=8)
    except asyncio.TimeoutError:
        client_banner = b""
    log_event(
        {
            "timestamp": utc_now(),
            "event_type": "banner_grab",
            "service": "ssh",
            "source_ip": source_ip,
            "source_port": source_port,
            "client_banner": client_banner.decode("utf-8", errors="replace").strip(),
        }
    )
    writer.close()
    await writer.wait_closed()


async def main() -> None:
    parser = argparse.ArgumentParser(description="Run the healthcare IoT deception honeypot")
    parser.add_argument("--config", default=str(PROFILE_PATH), help="Path to device profile JSON")
    args = parser.parse_args()

    ensure_dirs()
    profile = load_json(Path(args.config), {})
    network = profile["network"]
    bind_host = network.get("bind_host", "127.0.0.1")

    servers = [
        await asyncio.start_server(handle_http, bind_host, int(network["http_port"])),
        await asyncio.start_server(handle_telnet, bind_host, int(network["telnet_port"])),
        await asyncio.start_server(handle_ssh_banner, bind_host, int(network["ssh_port"])),
    ]

    print(json.dumps({"status": "running", "bind_host": bind_host, "ports": network}, indent=2))
    async with servers[0], servers[1], servers[2]:
        await asyncio.gather(*(server.serve_forever() for server in servers))


if __name__ == "__main__":
    asyncio.run(main())
