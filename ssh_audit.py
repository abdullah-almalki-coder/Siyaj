import json
import os

SSHD_CONFIG = "/etc/ssh/sshd_config"
CIS_RULES = os.path.join(os.path.dirname(__file__), "cis_rules.json")


def load_ssh_config():
    """قراءة ملف إعدادات SSH"""
    config = {}
    try:
        with open(SSHD_CONFIG, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        config[parts[0]] = parts[1]
    except FileNotFoundError:
        print(f"[!] ملف {SSHD_CONFIG} غير موجود")
    except PermissionError:
        print(f"[!] لا توجد صلاحية لقراءة {SSHD_CONFIG} — شغّل الأداة بـ sudo")
    return config


def evaluate_setting(rule, config):
    """تقييم إعداد واحد مقارنةً بالقاعدة"""
    setting = rule["setting"]
    expected = rule["expected"]
    operator = rule.get("operator", "eq")

    if setting not in config:
        return {
            "id": rule["id"],
            "setting": setting,
            "status": "مفقود",
            "current": None,
            "expected": expected,
            "severity": rule["severity"],
            "description": rule["description"],
            "recommendation": rule["recommendation"],
        }

    current = config[setting].strip().lower()
    expected_lower = expected.lower()

    if operator == "eq":
        passed = current == expected_lower
    elif operator == "lte":
        try:
            passed = int(current) <= int(expected)
        except ValueError:
            passed = False
    else:
        passed = current == expected_lower

    return {
        "id": rule["id"],
        "setting": setting,
        "status": "آمن" if passed else "خطر",
        "current": config[setting],
        "expected": expected,
        "severity": rule["severity"],
        "description": rule["description"],
        "recommendation": rule["recommendation"] if not passed else None,
    }


def calculate_score(results):
    """حساب درجة SSH من 100"""
    if not results:
        return 0

    weights = {"critical": 3, "high": 2, "medium": 1, "low": 0.5}
    total_weight = sum(weights.get(r["severity"], 1) for r in results)
    earned_weight = sum(
        weights.get(r["severity"], 1)
        for r in results
        if r["status"] == "آمن"
    )

    return round((earned_weight / total_weight) * 100) if total_weight else 0


def run():
    """تشغيل فحص SSH الكامل"""
    with open(CIS_RULES) as f:
        rules = json.load(f)["ssh"]

    config = load_ssh_config()
    results = [evaluate_setting(rule, config) for rule in rules]
    score = calculate_score(results)

    return {
        "module": "SSH",
        "score": score,
        "results": results,
        "config_path": SSHD_CONFIG,
    }
