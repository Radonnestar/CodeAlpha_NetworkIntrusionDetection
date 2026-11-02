import argparse
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
PORT = 8080
SCAN_PORTS = range(8000, 8040)
BRUTE_FORCE_ATTEMPTS = 8
REQUEST_TIMEOUT = 2


def fetch(host, path, method="GET", headers=None):
    request = urllib.request.Request(
        f"http://{host}:{PORT}{path}", method=method, headers=headers or {}
    )

    try:
        urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT).read()
    except urllib.error.HTTPError:
        return
    except (urllib.error.URLError, TimeoutError):
        sys.exit("Target server is not reachable. Start lab/target_server.py first.")


def sql_injection(host):
    fetch(host, "/search?q=" + urllib.parse.quote("1 UNION SELECT username,password FROM users"))
    fetch(host, "/search?q=" + urllib.parse.quote("admin' OR '1'='1"))


def cross_site_scripting(host):
    fetch(host, "/search?q=" + urllib.parse.quote("<script>alert(1)</script>"))


def path_traversal(host):
    fetch(host, "/search?q=../../../../etc/passwd")


def scanner_agent(host):
    fetch(host, "/", headers={"User-Agent": "sqlmap/1.7"})


def brute_force(host):
    for _ in range(BRUTE_FORCE_ATTEMPTS):
        fetch(host, "/login", method="POST")


def port_scan(host):
    for port in SCAN_PORTS:
        with socket.socket() as probe:
            probe.settimeout(0.1)
            probe.connect_ex((host, port))


ATTACKS = {
    "sqli": sql_injection,
    "xss": cross_site_scripting,
    "traversal": path_traversal,
    "scanner": scanner_agent,
    "bruteforce": brute_force,
    "portscan": port_scan,
}


def parse_arguments():
    parser = argparse.ArgumentParser(description="Lab-only attack simulator.")
    parser.add_argument("attack", choices=[*ATTACKS, "all"])
    parser.add_argument("--target", default="127.0.0.1")

    return parser.parse_args()


def main():
    arguments = parse_arguments()

    if arguments.target not in ALLOWED_HOSTS:
        sys.exit("Refusing to run: this simulator only targets localhost.")

    chosen = ATTACKS if arguments.attack == "all" else {arguments.attack: ATTACKS[arguments.attack]}

    for name, attack in chosen.items():
        print(f"Running {name}")
        attack(arguments.target)
        time.sleep(1)


if __name__ == "__main__":
    main()