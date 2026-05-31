import glob
import os
import subprocess


SSHD_CONFIG = "/etc/ssh/sshd_config"

# OpenSSH compiled-in defaults, used only as a fallback when `sshd -T`
# (which already resolves defaults) is unavailable. An absent directive is
# judged by its real default instead of being blindly penalised.
SSH_DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "x11forwarding": "no",
    "maxauthtries": "6",
    "ignorerhosts": "yes",
    "hostbasedauthentication": "no",
    "permitemptypasswords": "no",
    "protocol": "2",  # Protocol keyword removed in OpenSSH 7.0; SSH2 enforced
}


def audit_ssh(rules):
    ssh_rules = rules.get("ssh", {})
    total_weight = sum(r["weight"] for r in ssh_rules.values())

    config, source = _effective_config()

    if config is None:
        if os.path.exists(SSHD_CONFIG):
            config = _parse_sshd_config(SSHD_CONFIG)
            source = "file"
        else:
            # No effective config and no file => SSH server is not installed.
            # That means no SSH attack surface, so this is "not applicable",
            # NOT maximally insecure. Emit WARN with neutral (full) credit so
            # the domain is not unfairly penalised by 40 points.
            return [{
                "check": "sshd_config",
                "description": "SSH server configuration",
                "status": "WARN",
                "detail": "SSH server not installed - SSH controls not applicable",
                "score": total_weight,
                "max_score": total_weight,
            }]

    results = []
    for key, rule in ssh_rules.items():
        expected = rule["expected"]
        weight = rule["weight"]
        description = rule["description"]
        comparator = rule.get("comparator", "eq")
        lkey = key.lower()

        actual = config.get(lkey)
        from_default = False
        if actual is None and source == "file":
            # Directive not written in the file: judge it by the real default
            # rather than treating absence as an automatic failure.
            actual = SSH_DEFAULTS.get(lkey)
            from_default = True

        if actual is None:
            if key == "Protocol":
                # Removed in OpenSSH 7.0 and absent from `sshd -T`; SSH2 enforced.
                status, detail, earned = "PASS", "SSH2 enforced by default", weight
            else:
                status = "WARN"
                detail = f"Not set; default unknown (expected: {expected})"
                earned = 0
        else:
            passed = _compare(actual, expected, comparator)
            tag = " (default)" if from_default else ""
            if passed:
                status, detail, earned = "PASS", f"{actual}{tag}", weight
            else:
                status, detail, earned = "FAIL", f"{actual}{tag} (expected: {expected})", 0

        results.append({
            "check": key,
            "description": description,
            "status": status,
            "detail": detail,
            "score": earned,
            "max_score": weight,
        })

    return results


def _run(cmd):
    # LC_ALL=C forces English/byte output so literal string matches are stable
    # regardless of the server's configured locale.
    try:
        env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=10, env=env)
        return r.stdout
    except Exception:
        return ""


def _effective_config():
    """Return (config_dict, "effective") from `sshd -T`, which resolves all
    compiled-in defaults, or (None, None) if it cannot be obtained."""
    for cmd in ("sshd -T", "/usr/sbin/sshd -T", "/usr/bin/sshd -T"):
        out = _run(cmd)
        if not out.strip():
            continue
        config = {}
        for line in out.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                k = parts[0].lower()
                if k not in config:
                    config[k] = parts[1].strip()
        if config:
            return config, "effective"
    return None, None


def _compare(actual, expected, comparator):
    if comparator == "lte":
        try:
            return int(actual) <= int(expected)
        except ValueError:
            return False
    return actual.lower() == expected.lower()


def _parse_sshd_config(path):
    config = {}
    _read_config_file(path, config)
    return config


def _read_config_file(path, config):
    """Read one sshd_config file, follow Include directives, first-value-wins."""
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("include "):
                    pattern = line.split(None, 1)[1].strip()
                    for included in sorted(glob.glob(pattern)):
                        _read_config_file(included, config)
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    key = parts[0].lower()
                    if key not in config:  # sshd uses first occurrence
                        config[key] = parts[1].strip()
    except OSError:
        pass
