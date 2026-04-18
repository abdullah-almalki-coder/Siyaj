import json
from ssh_audit import audit_ssh, evaluate_ssh
from firewall_audit import audit_firewall, audit_ports, evaluate_firewall
from users_audit import audit_users, evaluate_users


def calculate_module_score(findings):
    """
    تحسب درجة أمان وحدة واحدة من 100.
    """
    scoreable = [f for f in findings if f['risk'] != 'للمراجعة']
    total = len(scoreable)
    if total == 0:
        return 0

    secure_count = sum(1 for f in scoreable if f['risk'] == 'لا يوجد')
    return int((secure_count / total) * 100)


def calculate_final_score(scores):
    """
    تحسب الدرجة النهائية الشاملة من 100 بناءً على أوزان كل وحدة.
    """
    weights = {
        'ssh': 0.40,
        'firewall': 0.35,
        'users': 0.25
    }

    final = 0
    for module, score in scores.items():
        weight = weights.get(module, 0)
        final += score * weight

    return int(final)


def get_risk_level(score):
    """
    تحدد مستوى الخطر بناءً على الدرجة.
    """
    if score >= 80:
        return {
            "level": "جيد",
            "color": "✅",
            "message": "الوضع الأمني جيد، استمر في المراقبة الدورية"
        }
    elif score >= 60:
        return {
            "level": "متوسط",
            "color": "⚠️",
            "message": "يحتاج تحسين، راجع التوصيات أعلاه"
        }
    elif score >= 40:
        return {
            "level": "خطر",
            "color": "🔴",
            "message": "وضع حرج، يجب المعالجة في أقرب وقت"
        }
    else:
        return {
            "level": "حرج",
            "color": "🚨",
            "message": "خطر شديد، السيرفر مكشوف للاختراق"
        }


def get_priority_issues(all_findings):
    """
    تستخرج أهم المشاكل التي يجب معالجتها أولاً.
    """
    critical_issues = []
    high_issues = []

    for module_name, findings in all_findings.items():
        for finding in findings:
            if finding['risk'] == 'حرج':
                critical_issues.append({
                    "module": module_name,
                    "setting": finding['setting'],
                    "description": finding['description'],
                    "remediation": finding['remediation']
                })
            elif finding['risk'] == 'عالي':
                high_issues.append({
                    "module": module_name,
                    "setting": finding['setting'],
                    "description": finding['description'],
                    "remediation": finding['remediation']
                })

    return critical_issues, high_issues


def run_scoring():
    """
    تشغل الفحص الكامل وتحسب الدرجات لجميع الوحدات.
    """
    all_findings = {}
    scores = {}

    # فحص SSH
    print("[*] جاري فحص SSH...")
    ssh_raw = audit_ssh()
    if "error" not in ssh_raw:
        ssh_findings = evaluate_ssh(ssh_raw)
        all_findings['ssh'] = ssh_findings
        scores['ssh'] = calculate_module_score(ssh_findings)
    else:
        print(f"[!] خطأ SSH: {ssh_raw['error']}")
        scores['ssh'] = 0

    # فحص الجدار الناري
    print("[*] جاري فحص الجدار الناري...")
    fw_raw = audit_firewall()
    ports_raw = audit_ports()
    fw_findings = evaluate_firewall(fw_raw, ports_raw)
    all_findings['firewall'] = fw_findings
    scores['firewall'] = calculate_module_score(fw_findings)

    # فحص المستخدمين
    print("[*] جاري فحص المستخدمين...")
    users_raw = audit_users()
    users_findings = evaluate_users(users_raw)
    all_findings['users'] = users_findings
    scores['users'] = calculate_module_score(users_findings)

    # الدرجة النهائية
    final_score = calculate_final_score(scores)

    return all_findings, scores, final_score


def print_score_report(all_findings, scores, final_score):
    """
    تطبع تقرير الدرجات الكامل في الطرفية.
    """
    print("\n" + "="*60)
    print("       🛡️  SecureConfig Auditor - تقرير التقييم")
    print("="*60)

    # درجات كل وحدة
    module_names = {
        'ssh': 'SSH',
        'firewall': 'الجدار الناري',
        'users': 'المستخدمون'
    }

    print("\n📊 درجات الوحدات:")
    print("-"*60)
    for module, score in scores.items():
        risk = get_risk_level(score)
        name = module_names.get(module, module)
        bar = "█" * (score // 10) + "░" * (10 - score // 10)
        print(f"  {risk['color']} {name:<20} [{bar}] {score}/100")

    # الدرجة النهائية
    final_risk = get_risk_level(final_score)
    print("\n" + "="*60)
    print(f"  📊 الدرجة النهائية الشاملة: {final_score}/100")
    print(f"  {final_risk['color']} المستوى: {final_risk['level']}")
    print(f"  💬 {final_risk['message']}")
    print("="*60)

    # أهم المشاكل
    critical_issues, high_issues = get_priority_issues(all_findings)

    if critical_issues:
        print("\n🚨 مشاكل حرجة يجب معالجتها فوراً:")
        print("-"*60)
        for issue in critical_issues:
            print(f"  ❌ [{issue['module'].upper()}] {issue['description']}")
            if issue['remediation']:
                print(f"     💡 {issue['remediation']}")

    if high_issues:
        print("\n🔴 مشاكل عالية الخطورة:")
        print("-"*60)
        for issue in high_issues:
            print(f"  ⚠️  [{issue['module'].upper()}] {issue['description']}")
            if issue['remediation']:
                print(f"     💡 {issue['remediation']}")

    print("="*60 + "\n")


if __name__ == "__main__":
    print("="*60)
    print("  🛡️  SecureConfig Auditor - نظام التقييم")
    print("="*60)

    all_findings, scores, final_score = run_scoring()
    print_score_report(all_findings, scores, final_score)
