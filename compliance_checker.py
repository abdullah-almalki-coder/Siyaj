import json

def load_rules(file_path="cis_rules.json"):
    """
    تحميل قواعد CIS من ملف JSON
    """
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"error": "cis_rules.json not found"}
    except Exception as e:
        return {"error": str(e)}


def check_ssh_compliance(ssh_data, rules):
    """
    مقارنة إعدادات SSH مع قواعد CIS
    """

    results = {}

    # إذا فيه خطأ في بيانات SSH
    if "error" in ssh_data:
        return {"error": ssh_data["error"]}

    ssh_rules = rules.get("ssh", {})

    for key, expected_value in ssh_rules.items():
        actual_value = ssh_data.get(key)

        # إذا الإعداد غير موجود
        if actual_value is None:
            results[key] = "NOT FOUND"
            continue

        # مقارنة القيم
        if str(actual_value).lower() == str(expected_value).lower():
            results[key] = "PASS"
        else:
            results[key] = "FAIL"

    return results


def run_compliance_checks(ssh_data):
    """
    تشغيل جميع اختبارات الـ Compliance
    """

    rules = load_rules()

    if "error" in rules:
        return rules

    results = {}

    # فحص SSH
    results["ssh"] = check_ssh_compliance(ssh_data, rules)

    return results
