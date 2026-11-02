# CodeAlpha Network Intrusion Detection System

A lab intrusion detection system built on Suricata. It detects web attacks and scans against a local target, automatically blocks the attacker, and shows everything on a live dashboard.

**Lab only.** Everything runs on 127.0.0.1. The attack simulator refuses any other target.

## Features

- Suricata with 7 custom rules, each tagged with a MITRE ATT&CK technique
- Behavioural detection: brute force and port scans use thresholds
- Automatic responder that blocks attackers with iptables
- Safety: dry-run by default, allowlist, temporary bans, only lab rules trigger a ban
- Live dashboard: alerts over time, top attackers, rules, ATT&CK techniques, alert feed and active bans

## Detection rules

| SID | Detects | MITRE |
| --- | --- | --- |
| 9000001 | SQL injection: UNION SELECT | T1190 |
| 9000002 | SQL injection: boolean tautology | T1190 |
| 9000003 | Cross-site scripting | T1059 |
| 9000004 | Path traversal | T1083 |
| 9000005 | Scanner user agent (sqlmap) | T1595 |
| 9000006 | Brute force: 5 logins in 10 s | T1110 |
| 9000007 | Port scan: 20 SYNs in 5 s | T1046 |

## Setup (Debian or Ubuntu, including WSL2)

```
sudo apt install -y suricata iptables python3 python3-venv
sudo suricata-update
python3 -m venv .venv
. .venv/bin/activate
pip install flask
sudo cp rules/local.rules /var/lib/suricata/rules/local.rules
```

Add `- local.rules` under `rule-files:` in `/etc/suricata/suricata.yaml`, then test:

```
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

## Run

Use one terminal for each:

| Terminal | Command |
| --- | --- |
| Target | `.venv/bin/python lab/target_server.py` |
| Suricata | `sudo suricata -c /etc/suricata/suricata.yaml -i lo` |
| Responder | `sudo .venv/bin/python responder/responder.py --block-loopback --enforce --ban-seconds 60` |
| Dashboard | `sudo .venv/bin/python dashboard/server.py` |
| Attacks | `.venv/bin/python lab/attack_simulator.py all` |

Open http://127.0.0.1:9000 for the dashboard. Omit `--enforce` for a dry run.

Attacker and defender share 127.0.0.1 in this lab, so an active ban also blocks your own requests to port 8080. Clear it any time:

```
sudo iptables -F LAB_BLOCK
```

## Structure

```
rules/       Suricata rules
lab/         target server and attack simulator
responder/   automatic blocking
dashboard/   live web dashboard
```
