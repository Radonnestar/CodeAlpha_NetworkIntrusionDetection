import json
import time
from collections import Counter
from pathlib import Path

from flask import Flask, jsonify

EVE_LOG = Path("/var/log/suricata/eve.json")
BANS_FILE = Path(__file__).resolve().parent.parent / "responder" / "bans.json"
LAB_SID_RANGE = range(9000000, 9001000)
TAIL_BYTES = 4_000_000
WINDOW_SECONDS = 300
BUCKET_SECONDS = 10
FEED_SIZE = 12

app = Flask(__name__, static_folder="static", static_url_path="")


def read_alerts():
    if not EVE_LOG.is_file():
        return []

    with EVE_LOG.open("rb") as handle:
        handle.seek(0, 2)
        handle.seek(max(0, handle.tell() - TAIL_BYTES))
        lines = handle.read().decode("utf-8", errors="ignore").splitlines()

    alerts = []

    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        alert = event["alert"]

        if alert["signature_id"] in LAB_SID_RANGE:
            alerts.append(
                {
                    "time": event["timestamp"],
                    "ip": event["src_ip"],
                    "signature": alert["signature"],
                    "sid": alert["signature_id"],
                    "technique": alert.get("metadata", {}).get("mitre_technique", ["unknown"])[0],
                    "severity": alert["severity"],
                }
            )

    return alerts


def read_bans():
    try:
        bans = json.loads(BANS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    now = time.time()

    return [
        {"ip": ban["ip"], "reason": ban["reason"], "seconds_left": int(ban["until"] - now)}
        for ban in bans
        if ban["until"] > now
    ]


def timeline(alerts):
    now = int(time.time())
    buckets = WINDOW_SECONDS // BUCKET_SECONDS
    counts = [0] * buckets

    for alert in alerts:
        stamp = time.mktime(time.strptime(alert["time"][:19], "%Y-%m-%dT%H:%M:%S"))
        age = now - int(stamp)

        if 0 <= age < WINDOW_SECONDS:
            counts[buckets - 1 - age // BUCKET_SECONDS] += 1

    return counts


def top(alerts, key, limit):
    return [{"name": name, "count": count} for name, count in Counter(a[key] for a in alerts).most_common(limit)]


@app.get("/api/stats")
def stats():
    alerts = read_alerts()

    return jsonify(
        total=len(alerts),
        timeline=timeline(alerts),
        attackers=top(alerts, "ip", 5),
        rules=top(alerts, "signature", 8),
        techniques=top(alerts, "technique", 8),
        feed=alerts[-FEED_SIZE:][::-1],
        bans=read_bans(),
    )


@app.get("/")
def index():
    return app.send_static_file("index.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9000)