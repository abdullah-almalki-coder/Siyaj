import os
import subprocess


def run_command(command):
    """
    تنفذ هذه الدالة أمر في الطرفية وترجع النتيجة.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    except Exception as e:
        return None


def audit_users():
    """
    تفحص هذه الدالة حسابات المستخدمين على السيرفر.
    """
    results = {}

    # فحص حالة حساب Root
    root_status = run_command("sudo passwd -S root | awk '{print $2}'")
    results['root_password'] = 'locked' if root_status in ['L', 'LK'] else 'unlocked'

    # فحص الحسابات التي لها صلاحيات Sudo
    sudo_users = run_command("getent group sudo | cut -d: -f4")
    if sudo_users:
        results['sudo_users'] = [u.strip() for u in sudo_users.split(',') if u.strip()]
    else:
        results['sudo_users'] = []

    # فحص الحسابات بكلمات مرور فارغة
    empty_passwords = run_command(
        "sudo awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow"
    )
    if empty_passwords:
        results['empty_passwords'] = [u.strip() for u in empty_passwords.split('\n') if u.strip()]
    else:
        results['empty_passwords'] = []

    # فحص الحسابات التي لها UID = 0 (صلاحيات Root)
    uid_zero = run_command(
        "awk -F: '($3 == 0) {print $1}' /etc/passwd"
    )
    if uid_zero:
        results['uid_zero_accounts'] = [u.strip() for u in uid_zero.split('\n') if u.strip()]
    else:
        results['uid_zero_accounts'] = []

    # فحص الحسابات غير النشطة منذ أكثر من 90 يوم
    inactive_users = run_command(
        "sudo lastlog | awk 'NR>1 && $0 !~ /Never/ {print $1}' | head -20"
    )
    if inactive_users:
        results['inactive_users'] = [u.strip() for u in inactive_users.split('\n') if u.strip()]
    else:
        results['inactive_users'] = []

    # فحص الحسابات التي لها shell تفاعلي
    shell_users = run_command(
        "awk -F: '$7 !~ /nologin|false/ {print $1}' /etc/passwd"
    )
    if shell_users:
        results['shell_users'] = [u.strip() for u in shell_users.split('\n') if u.strip()]
    else:
        results['shell_users'] = []

    return results


def evaluate_users(results):
    """
    تقيّم هذه الدالة نتائج فحص المستخدمين.
    """
    findings = []

    # تقييم حالة حساب Root
    root_status = results.get('root_password', 'unknown')
    findings.append({
        "setting": "root_password",
        "description": "حالة قفل حساب Root",
        "actual_value": "مقفل ✅" if root_status == 'locked' else "غير مقفل ❌",
        "expected_value": "مقفل",
        "status": "✅ آمن" if root_status == 'locked' else "🔴 خطر",
        "risk": "لا يوجد" if root_status == 'locked' else "عالي",
        "remediation": "sudo passwd -l root" if root_status != 'locked' else None
    })

    # تقييم حسابات Sudo
    sudo_users = results.get('sudo_users', [])
    findings.append({
        "setting": "sudo_group",
        "description": "المستخدمون الذين لهم صلاحيات Sudo",
        "actual_value": ', '.join(sudo_users) if sudo_users else "لا يوجد",
        "expected_value": "مستخدمون موثوقون فقط",
        "status": "📋 للمراجعة",
        "risk": "للمراجعة",
        "remediation": "راجع القائمة وأزل أي مستخدم غير ضروري: sudo deluser [username] sudo"
    })

    # تقييم كلمات المرور الفارغة
    empty_passwords = results.get('empty_passwords', [])
    findings.append({
        "setting": "empty_passwords",
        "description": "حسابات بكلمات مرور فارغة أو معطلة",
        "actual_value": ', '.join(empty_passwords) if empty_passwords else "لا يوجد",
        "expected_value": "لا يوجد",
        "status": "✅ آمن" if not empty_passwords else "🔴 خطر",
        "risk": "لا يوجد" if not empty_passwords else "عالي",
        "remediation": "قم بتعيين كلمة مرور أو تعطيل الحساب: sudo passwd [username]" if empty_passwords else None
    })

    # تقييم حسابات UID = 0
    uid_zero = results.get('uid_zero_accounts', [])
    non_root_uid_zero = [u for u in uid_zero if u != 'root']
    findings.append({
        "setting": "uid_zero_accounts",
        "description": "حسابات تملك صلاحيات Root (UID=0)",
        "actual_value": ', '.join(uid_zero) if uid_zero else "root فقط",
        "expected_value": "root فقط",
        "status": "✅ آمن" if not non_root_uid_zero else "🔴 خطر",
        "risk": "لا يوجد" if not non_root_uid_zero else "حرج",
        "remediation": "احذف أو عدّل الحسابات غير المصرح بها التي تملك UID=0" if non_root_uid_zero else None
    })

    # تقييم الحسابات التي لها Shell تفاعلي
    shell_users = results.get('shell_users', [])
    findings.append({
        "setting": "shell_users",
        "description": "الحسابات التي لها Shell تفاعلي",
        "actual_value": ', '.join(shell_users) if shell_users else "لا يوجد",
        "expected_value": "مستخدمون ضروريون فقط",
        "status": "📋 للمراجعة",
        "risk": "للمراجعة",
        "remediation": "عطّل Shell للحسابات غير الضرورية: sudo usermod -s /sbin/nologin [username]"
    })

    return findings


def calculate_users_score(findings):
    """
    تحسب درجة أمان المستخدمين من 100.
    """
    scoreable = [f for f in findings if f['risk'] != 'للمراجعة']
    total = len(scoreable)
    if total == 0:
        return 0

    secure_count = sum(1 for f in scoreable if f['risk'] == 'لا يوجد')
    return int((secure_count / total) * 100)


if __name__ == "__main__":
    print("[-] جاري فحص حسابات المستخدمين...")

    results = audit_users()
    findings = evaluate_users(results)
    score = calculate_users_score(findings)

    print("\n" + "="*60)
    print("       🛡️  تقرير فحص حسابات المستخدمين")
    print("="*60)

    for finding in findings:
        print(f"\n🔧 الإعداد        : {finding['setting']}")
        print(f"   الوصف          : {finding['description']}")
        print(f"   القيمة الحالية  : {finding['actual_value']}")
        print(f"   القيمة المطلوبة : {finding['expected_value']}")
        print(f"   الحالة          : {finding['status']}")
        print(f"   مستوى الخطر     : {finding['risk']}")
        if finding['remediation']:
            print(f"   💡 التوصية      : {finding['remediation']}")
        print("-"*60)

    print(f"\n📊 درجة أمان المستخدمين: {score}/100")
    print("="*60 + "\n")
