import os
import pwd
import subprocess


def audit_users(rules):
    u_rules = rules.get("users", {})
    results = []

    # Root locked
    weight = u_rules.get("root_locked", {}).get("weight", 10)
    locked = _root_locked()
    results.append({
        "check": "root_locked",
        "description": u_rules.get("root_locked", {}).get("description", ""),
        "status": "PASS" if locked else "FAIL",
        "detail": "locked" if locked else "NOT locked",
        "score": weight if locked else 0,
        "max_score": weight,
    })

    # No UID=0 non-root accounts
    weight = u_rules.get("no_uid0_non_root", {}).get("weight", 8)
    uid0 = _uid0_non_root()
    results.append({
        "check": "no_uid0_non_root",
        "description": u_rules.get("no_uid0_non_root", {}).get("description", ""),
        "status": "PASS" if not uid0 else "FAIL",
        "detail": "None found" if not uid0 else f"Found: {', '.join(uid0)}",
        "score": weight if not uid0 else 0,
        "max_score": weight,
    })

    # No empty passwords — None means permission denied (not the same as no issues)
    weight = u_rules.get("no_empty_passwords", {}).get("weight", 4)
    empty = _empty_passwords()
    if empty is None:
        status, detail, earned = "WARN", "Cannot read /etc/shadow (run as root)", 0
    elif not empty:
        status, detail, earned = "PASS", "None found", weight
    else:
        status, detail, earned = "FAIL", f"Found: {', '.join(empty)}", 0
    results.append({
        "check": "no_empty_passwords",
        "description": u_rules.get("no_empty_passwords", {}).get("description", ""),
        "status": status,
        "detail": detail,
        "score": earned,
        "max_score": weight,
    })

    # No NOPASSWD sudo rules — None means no sudoers file was readable
    weight = u_rules.get("no_nopasswd_sudo", {}).get("weight", 3)
    nopasswd = _nopasswd_sudo()
    if nopasswd is None:
        status, detail, earned = "WARN", "Cannot read sudoers (run as root)", 0
    elif not nopasswd:
        status, detail, earned = "PASS", "None found", weight
    else:
        status, detail, earned = "FAIL", f"{len(nopasswd)} NOPASSWD rule(s) found", 0
    results.append({
        "check": "no_nopasswd_sudo",
        "description": u_rules.get("no_nopasswd_sudo", {}).get("description", ""),
        "status": status,
        "detail": detail,
        "score": earned,
        "max_score": weight,
    })

    return results


def _run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""


def _root_locked():
    out = _run("passwd -S root")
    if out:
        parts = out.split()
        if len(parts) >= 2 and parts[1] in ("L", "LK"):
            return True

    try:
        with open("/etc/shadow", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if parts[0] == "root" and len(parts) >= 2:
                    return parts[1].startswith("!") or parts[1].startswith("*")
    except OSError:
        pass

    return False


def _uid0_non_root():
    try:
        return [e.pw_name for e in pwd.getpwall() if e.pw_uid == 0 and e.pw_name != "root"]
    except Exception:
        return []


def _empty_passwords():
    """Return list of accounts with empty passwords, or None if /etc/shadow is unreadable."""
    try:
        accounts = []
        with open("/etc/shadow", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2 and parts[1] == "":
                    accounts.append(parts[0])
        return accounts
    except PermissionError:
        return None
    except OSError:
        return None


def _nopasswd_sudo():
    """Return list of NOPASSWD rules, or None if no sudoers file could be read."""
    hits = []
    any_readable = False
    candidates = ["/etc/sudoers"]

    sudoers_d = "/etc/sudoers.d"
    if os.path.isdir(sudoers_d):
        for name in os.listdir(sudoers_d):
            candidates.append(os.path.join(sudoers_d, name))

    for path in candidates:
        try:
            with open(path, "r") as f:
                any_readable = True
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#") and "NOPASSWD" in stripped:
                        hits.append(stripped)
        except OSError:
            pass

    if not any_readable:
        return None
    return hits
