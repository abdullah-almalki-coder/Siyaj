import glob
import os


SSHD_CONFIG = "/etc/ssh/sshd_config"


def audit_ssh(rules):
    ssh_rules = rules.get("ssh", {})

    if not os.path.exists(SSHD_CONFIG):
        return [{
            "check": "sshd_config",
            "description": "SSH daemon configuration file",
            "status": "FAIL",
            "detail": f"{SSHD_CONFIG} not found",
            "score": 0,
            "max_score": sum(r["weight"] for r in ssh_rules.values()),
        }]

    config = _parse_sshd_config(SSHD_CONFIG)
    results = []

    for key, rule in ssh_rules.items():
        expected = rule["expected"]
        weight = rule["weight"]
        description = rule["description"]
        comparator = rule.get("comparator", "eq")

        actual = config.get(key.lower())

        if actual is None:
            # Protocol was removed in OpenSSH 7.0 — absence means SSH2-only (safe by default)
            if key == "Protocol":
                status = "PASS"
                detail = "Not in config (SSH2 enforced by default)"
                earned = weight
            else:
                status = "WARN"
                detail = f"Not set in config (expected: {expected})"
                earned = 0
        else:
            passed = _compare(actual, expected, comparator)
            if passed:
                status = "PASS"
                detail = actual
                earned = weight
            else:
                status = "FAIL"
                detail = f"{actual} (expected: {expected})"
                earned = 0

        results.append({
            "check": key,
            "description": description,
            "status": status,
            "detail": detail,
            "score": earned,
            "max_score": weight,
        })

    return results


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
