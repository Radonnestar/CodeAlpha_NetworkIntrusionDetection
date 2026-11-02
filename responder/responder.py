import argparse
import ipaddress
import json
import subprocess
import time
from pathlib import Path

EVE_LOG = Path("/var/log/suricata/eve.json")
BANS_FILE = Path(__file__).resolve().parent / "bans.json"
LAB_SID_RANGE = range(9000000, 9001000)
CHAIN = "LAB_BLOCK"
BAN_SECONDS = 60
POLL_SECONDS = 0.5
ALWAYS_ALLOWED = {"127.0.0.1", "::1"}


def parse_arguments():
    parser = argparse.ArgumentParser(description="Lab-only automatic responder.")
    parser.add_argument("--enforce", action="store_true", help="apply real firewall rules")
    parser.add_argument("--block-loopback", action="store_true", help="allow banning 127.0.0.1")
    parser.add_argument("--ban-seconds", type=int, default=BAN_SECONDS)
    parser.add_argument("--allow", nargs="*", default=[], help="extra IPs that are never blocked")

    return parser.parse_args()


def run(command):
    return subprocess.run(command, capture_output=True, text=True, check=False)


def prepare_chain():
    run(["iptables", "-N", CHAIN])

    if run(["iptables", "-C", "INPUT", "-j", CHAIN]).returncode != 0:
        run(["iptables", "-I", "INPUT", "1", "-j", CHAIN])


def rule_arguments(address):
    return [CHAIN, "-s", address, "-p", "tcp", "--dport", "8080", "-j", "DROP"]


def block(address):
    if run(["iptables", "-C", *rule_arguments(address)]).returncode == 0:
        return

    result = run(["iptables", "-A", *rule_arguments(address)])

    if result.returncode != 0:
        print(f"FIREWALL ERROR: {result.stderr.strip()}", flush=True)


def unblock(address):
    run(["iptables", "-D", *rule_arguments(address)])


def is_valid_address(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False

    return True


def publish(bans):
    payload = [
        {"ip": ip, "until": ban["until"], "reason": ban["reason"]} for ip, ban in bans.items()
    ]

    BANS_FILE.write_text(json.dumps(payload), encoding="utf-8")


def follow(path):
    with path.open(encoding="utf-8") as handle:
        handle.seek(0, 2)

        while True:
            line = handle.readline()
            yield line or None

            if not line:
                time.sleep(POLL_SECONDS)


def parse_alert(line):
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None

    if event.get("event_type") != "alert":
        return None

    alert = event["alert"]

    if alert["signature_id"] not in LAB_SID_RANGE:
        return None

    return event["src_ip"], alert["signature"]


def expire(bans, enforce):
    now = time.time()
    expired = [ip for ip, ban in bans.items() if ban["until"] <= now]

    for address in expired:
        del bans[address]

        if enforce:
            unblock(address)

        print(f"UNBLOCKED {address} (ban expired)", flush=True)

    if expired:
        publish(bans)


def main():
    arguments = parse_arguments()
    allowed = ALWAYS_ALLOWED - ({"127.0.0.1"} if arguments.block_loopback else set())
    allowed |= set(arguments.allow)
    bans = {}

    if arguments.enforce:
        prepare_chain()

    publish(bans)

    mode = "ENFORCE" if arguments.enforce else "DRY-RUN"
    print(f"Responder started ({mode}), watching {EVE_LOG}", flush=True)

    for line in follow(EVE_LOG):
        expire(bans, arguments.enforce)
        alert = parse_alert(line) if line else None

        if alert is None:
            continue

        address, signature = alert

        if not is_valid_address(address) or address in allowed or address in bans:
            continue

        bans[address] = {"until": time.time() + arguments.ban_seconds, "reason": signature}

        if arguments.enforce:
            block(address)

        publish(bans)
        print(f"BLOCKED {address} for {arguments.ban_seconds}s: {signature}", flush=True)


if __name__ == "__main__":
    main()