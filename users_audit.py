import subprocess
import json
import os

CIS_RULES = os.path.join(os.path.dirname(__file__), "cis_rules.json")


def get_all_users():
    """قراءة جميع المستخدمين من /etc/passwd"""
    users = []
    try:
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    users.append({
                        "username": parts[0],
                        "uid": int(parts[2]),
                        "gid": int(parts[3]),
                        "shell": parts[6],
                    })
    except Exception as e:
        print(f"[!] خطأ في قراءة /etc/passwd: {e}")
    return users


def check_root_locked():
    """التحقق من قفل حساب Root"""
    try:
        result = subprocess.run(
            ["passwd", "-S", "root"],
            capture_output=True, text=True
        )
        # L = Locked, P = Password set, NP = No Password
        return "L" in result.stdout.split()[1] if result.stdout else False
    except Exception:
        return False


def check_uid_zero(users):
    """البحث عن حسابات بـ UID=0 غير Root"""
    return [u for u in users if u["uid"] == 0 and u["username"] != "root"]


def check_empty_passwords():
    """البحث عن حسابات بكلمات مرور فارغة"""
    empty = []
    try:
        with open("/etc/shadow") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 2 and parts[1] == "":
                    empty.append(parts[0])
    except PermissionError:
        print("[!] لا توجد صلاحية لقراءة /etc/shadow — شغّل الأداة بـ sudo")
    except FileNotFoundError:
        pass
    return empty


def check_sudo_nopasswd():
    """البحث عن مستخدمين بصلاحية NOPASSWD في sudoers"""
    nopasswd_users = []
    sudoers_files = ["/etc/sudoers"]

    sudoers_dir = "/etc/sudoers.d"
    if os.path.isdir(sudoers_dir):
        for fname in os.listdir(sudoers_dir):
            sudoers_files.append(os.path.join(sudoers_dir, fname))

    for fpath in sudoers_files:
        try:
            with open(fpath) as f:
                for line in f:
                    line = line.strip()
                    if "NOPASSWD" in line and not line.startswith("#"):
                        nopasswd_users.append(line)
        except Exception:
            pass

    return nopasswd_users


def calculate_score(root_locked, uid_zero_list, empty_pw_list, nopasswd_list):
    """حساب درجة المستخدمين"""
    score = 100

    if not root_locked:
        score -= 25
    score -= len(uid_zero_list) * 30
    score -= len(empty_pw_list) * 25
    score -= len(nopasswd_list) * 10

    return max(0, score)


def run():
    """تشغيل فحص المستخدمين الكامل"""
    users = get_all_users()
    root_locked = check_root_locked()
    uid_zero_list = check_uid_zero(users)
    empty_pw_list = check_empty_passwords()
    nopasswd_list = check_sudo_nopasswd()

    score = calculate_score(root_locked, uid_zero_list, empty_pw_list, nopasswd_list)

    results = []

    results.append({
        "check": "قفل حساب Root",
        "status": "آمن" if root_locked else "خطر",
        "detail": "حساب Root مقفل" if root_locked else "حساب Root غير مقفل!",
        "severity": "high",
        "recommendation": None if root_locked else "أقفل Root: sudo passwd -l root",
    })

    results.append({
        "check": "حسابات بـ UID=0",
        "status": "آمن" if not uid_zero_list else "خطر",
        "detail": (f"وُجدت حسابات خطيرة: {[u['username'] for u in uid_zero_list]}"
                   if uid_zero_list else "لا توجد حسابات إضافية بـ UID=0"),
        "severity": "critical",
        "recommendation": ("احذف أو عدّل هذه الحسابات فوراً"
                           if uid_zero_list else None),
    })

    results.append({
        "check": "كلمات المرور الفارغة",
        "status": "آمن" if not empty_pw_list else "خطر",
        "detail": (f"حسابات بدون كلمة مرور: {empty_pw_list}"
                   if empty_pw_list else "جميع الحسابات لها كلمات مرور"),
        "severity": "critical",
        "recommendation": ("اضبط كلمة مرور لكل حساب: sudo passwd <اسم_المستخدم>"
                           if empty_pw_list else None),
    })

    results.append({
        "check": "صلاحيات Sudo بدون مرور",
        "status": "آمن" if not nopasswd_list else "تحذير",
        "detail": (f"وُجدت {len(nopasswd_list)} قاعدة NOPASSWD في sudoers"
                   if nopasswd_list else "لا توجد صلاحيات NOPASSWD"),
        "severity": "high",
        "recommendation": ("راجع ملف sudoers وأزل NOPASSWD حيث أمكن"
                           if nopasswd_list else None),
    })

    return {
        "module": "Users",
        "score": score,
        "results": results,
        "total_users": len(users),
    }
