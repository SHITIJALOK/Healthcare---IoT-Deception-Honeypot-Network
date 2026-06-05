from __future__ import annotations

import argparse
import ipaddress
import uuid

from common import CONFIG_DIR, append_jsonl, ensure_dirs, load_json, utc_now, write_json


RULES_PATH = CONFIG_DIR / "firewall_rules.json"
AUDIT_LOG = CONFIG_DIR / "firewall_audit.jsonl"


def load_rules() -> dict:
    return load_json(RULES_PATH, {"active": [], "rolled_back": []})


def save_rules(data: dict) -> None:
    write_json(RULES_PATH, data)


def validate_ip(ip: str) -> str:
    return str(ipaddress.ip_address(ip))


def block(ip: str, reason: str) -> dict:
    data = load_rules()
    ip = validate_ip(ip)
    existing = next((rule for rule in data["active"] if rule["ip"] == ip), None)
    if existing:
        return existing

    rule = {
        "id": str(uuid.uuid4()),
        "ip": ip,
        "reason": reason,
        "created_at": utc_now(),
        "status": "active",
        "mode": "simulated",
    }
    data["active"].append(rule)
    save_rules(data)
    append_jsonl(AUDIT_LOG, {"timestamp": utc_now(), "action": "block", "rule": rule})
    return rule


def rollback(ip: str) -> dict:
    data = load_rules()
    ip = validate_ip(ip)
    for index, rule in enumerate(data["active"]):
        if rule["ip"] == ip:
            removed = data["active"].pop(index)
            removed["status"] = "rolled_back"
            removed["rolled_back_at"] = utc_now()
            data["rolled_back"].append(removed)
            save_rules(data)
            append_jsonl(AUDIT_LOG, {"timestamp": utc_now(), "action": "rollback", "rule": removed})
            return removed
    raise SystemExit(f"No active simulated rule found for {ip}")


def main() -> None:
    ensure_dirs()
    parser = argparse.ArgumentParser(description="Manage simulated firewall block rules")
    sub = parser.add_subparsers(dest="command", required=True)

    block_parser = sub.add_parser("block")
    block_parser.add_argument("ip")
    block_parser.add_argument("reason")

    rollback_parser = sub.add_parser("rollback")
    rollback_parser.add_argument("ip")

    sub.add_parser("list")
    args = parser.parse_args()

    if args.command == "block":
        print(block(args.ip, args.reason))
    elif args.command == "rollback":
        print(rollback(args.ip))
    elif args.command == "list":
        print(load_rules())


if __name__ == "__main__":
    main()
