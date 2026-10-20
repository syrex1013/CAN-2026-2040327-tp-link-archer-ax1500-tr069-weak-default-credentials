# CVE Submission: TP-Link Archer AX1500 TR-069 Weak Default Credentials

## Summary

TP-Link Archer AX1500 (and likely other AX/EX series) exposes a CWMP
Connection Request endpoint on LAN port 7547 protected by HTTP Digest auth
with hardcoded credentials `admin/admin`, independent of the device's
admin interface password. Any LAN-side attacker can authenticate and trigger
a CWMP session without knowing the router's actual admin password.

## Affected Products

- TP-Link Archer AX1500 v1.20
- Firmware: 1.3.12 Build 20250828 Rel. 26873(4555) (OpenWrt-based)
- Likely affected: all TP-Link AX/EX series with TR-069 CWMP enabled

## Vulnerability Details

**CWE**: CWE-1391 (Use of Weak Credentials) / CWE-798 (Use of Hard-coded Credentials)

**CVSS v3.1**: 7.6 (HIGH)
- Vector: AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L
- Adjacent (LAN) attacker, no auth needed (beyond weak default), no user interaction

### Technical Details

The router runs a TR-069/CWMP HTTP server on port 7547 (lan-side).
The Connection Request URL `/tr069` accepts HTTP Digest authentication
with realm `tp-link.com.cn`. The credentials are hardcoded as `admin/admin`
and do NOT change when the router admin password is modified.

```
GET /tr069 HTTP/1.1
Host: 192.168.0.2:7547
→ 401 WWW-Authenticate: Digest realm="tp-link.com.cn", nonce="...", algorithm="MD5", qop="auth"

GET /tr069 HTTP/1.1 (with Digest auth admin:admin)
→ 200 OK (connection request accepted)
```

After accepting the connection request, the CPE initiates a CWMP session
to the configured ACS (Auto Configuration Server) URL. If the ACS URL is
controllable (via a separate attack or misconfiguration), an attacker gains
full management-plane access via CWMP SetParameterValues — enabling firmware
download, credential extraction, DNS hijacking, and full RCE.

### Impact

- **Primary**: Unauthorized CWMP Connection Request trigger from any LAN host
- **Chained**: If ACS URL is misconfigured/local, achieves full device takeover
- **Scope**: All LAN-connected devices; router admin password provides NO protection

## Timeline

- **2026-10-21**: Discovered during authorized security testing
- **Submitted to**: MITRE CVE Program, TP-Link PSIRT

## References

- TP-Link PSIRT: security@tp-link.com
- TR-069 CPE WAN Management Protocol: https://www.broadband-forum.org/technical/download/TR-069.pdf
