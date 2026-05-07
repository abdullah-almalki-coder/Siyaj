import json
import os
import subprocess

CIS_RULES = os.path.join(os.path.dirname(__file__), "cis_rules.json")


def get_ufw_status():
    """فحص حالة UFW"""
    try:
        result = subprocess.run(
            ["ufw", "status", "verbose"],
            capture_output=True, text=True
        )
        output = result.stdout.lower()
        active = "status: active" in output
        default_deny = "default: deny" in output or "default: reject" in output
        return active, default_deny, result.stdout
    except FileNotFoundError:
        return False, False, "UFW غير مثبت"


def get_open_ports():
    """الحصول على المنافذ المفتوحة"""
    ports = []
    try:
        result = subprocess.run(
            ["ss", "-tuln"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                addr = parts[4]
                port_str = addr.rsplit(":", 1)[-1]
                try:
                    ports.append(int(port_str))
                except ValueError:
                    pass
    except Exception:
        pass
    return list(set(ports))


def check_dangerous_ports(open_ports, dangerous_ports):
    """مقارنة المنافذ المفتوحة مع قائمة المنافذ الخطيرة"""
    found = []
    for dp in dangerous_ports:
        if dp["port"] in open_ports:
            found.append(dp)
    return found


def calculate_score(ufw_active, default_deny, dangerous_found):
    """حساب درجة الجدار الناري"""
    score = 100

    if not ufw_active:
        score -= 50
    if not default_deny:
        score -= 20

    severity_penalty = {"critical": 15, "high": 10, "medium": 5}
    for port in dangerous_found:
        score -= severity_penalty.get(port["severity"], 5)

    return max(0, score)


def run():
    """تشغيل فحص الجدار الناري الكامل"""
    with open(CIS_RULES) as f:
        dangerous_ports = json.load(f)["firewall"]["dangerous_ports"]

    ufw_active, default_deny, ufw_output = get_ufw_status()
    open_ports = get_open_ports()
    dangerous_found = check_dangerous_ports(open_ports, dangerous_ports)
    score = calculate_score(ufw_active, default_deny, dangerous_found)

    results = []

    results.append({
        "check": "حالة UFW",
        "status": "آمن" if ufw_active else "خطر",
        "detail": "الجدار الناري نشط" if ufw_active else "الجدار الناري غير نشط!",
        "severity": "critical",
        "recommendation": None if ufw_active else "شغّل UFW: sudo ufw enable",
    })

    results.append({
        "check": "السياسة الافتراضية",
        "status": "آمن" if default_deny else "خطر",
        "detail": "الإعداد الافتراضي: رفض الاتصالات الواردة" if default_deny
                  else "الإعداد الافتراضي يسمح بالاتصالات الواردة!",
        "severity": "high",
        "recommendation": None if default_deny
                          else "اضبط السياسة: sudo ufw default deny incoming",
    })

    for port in dangerous_found:
        results.append({
            "check": f"منفذ خطير: {port['name']} ({port['port']})",
            "status": "خطر",
            "detail": port["reason"],
            "severity": port["severity"],
            "recommendation": f"أغلق المنفذ: sudo ufw deny {port['port']}",
        })

    return {
        "module": "Firewall",
        "score": score,
        "results": results,
        "open_ports": open_ports,
        "ufw_active": ufw_active,
    }
