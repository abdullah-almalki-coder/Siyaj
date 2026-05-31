import os
import re
import subprocess


def audit_firewall(rules):
    fw_rules = rules.get("firewall", {})
    results = []

    # UFW active
    weight = fw_rules.get("ufw_active", {}).get("weight", 15)
    active = _ufw_active()
    results.append({
        "check": "ufw_active",
        "description": fw_rules.get("ufw_active", {}).get("description", ""),
        "status": "PASS" if active else "FAIL",
        "detail": "active" if active else "inactive or not installed",
        "score": weight if active else 0,
        "max_score": weight,
    })

    # Default incoming deny
    weight = fw_rules.get("default_incoming_deny", {}).get("weight", 10)
    deny = _default_deny()
    results.append({
        "check": "default_incoming_deny",
        "description": fw_rules.get("default_incoming_deny", {}).get("description", ""),
        "status": "PASS" if deny else "FAIL",
        "detail": "deny" if deny else "not set to deny",
        "score": weight if deny else 0,
        "max_score": weight,
    })

    # Dangerous open ports
    dp_rule = fw_rules.get("dangerous_ports", {})
    weight = dp_rule.get("weight", 10)
    ports = dp_rule.get("ports", [])
    open_dangerous = _open_dangerous_ports(ports)

    if open_dangerous:
        status, detail, earned = "FAIL", f"Open: {', '.join(map(str, open_dangerous))}", 0
    else:
        status, detail, earned = "PASS", "No dangerous ports open", weight

    results.append({
        "check": "dangerous_ports",
        "description": dp_rule.get("description", ""),
        "status": status,
        "detail": detail,
        "score": earned,
        "max_score": weight,
    })

    return results


def _run(cmd):
    # LC_ALL=C forces English output so matches like "Status: active" and
    # "deny (incoming)" are stable regardless of the server's locale.
    try:
        env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=10, env=env)
        return r.stdout + r.stderr
    except Exception:
        return ""


def _ufw_active():
    out = _run("ufw status")
    return "Status: active" in out


def _default_deny():
    out = _run("ufw status verbose")
    lower = out.lower()
    return "deny (incoming)" in lower or "default: deny" in lower


def _open_dangerous_ports(ports):
    out = _run("ss -tlnp")
    if not out.strip():
        out = _run("netstat -tlnp")
    return [p for p in ports if re.search(rf"[:\s]{p}[\s\t]", out)]
