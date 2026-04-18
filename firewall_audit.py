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


def audit_firewall():
    """
    تفحص هذه الدالة إعدادات الجدار الناري (UFW/iptables).
    """
    results = {}

    # فحص حالة UFW
    ufw_status = run_command("sudo ufw status | head -1")
    if ufw_status:
        results['ufw_status'] = 'active' if 'active' in ufw_status.lower() else 'inactive'
    else:
        results['ufw_status'] = 'not_installed'

    # فحص السياسة الافتراضية للاتصالات الواردة
    default_policy = run_command("sudo ufw status verbose | grep 'Default:'")
    if default_policy:
        results['default_incoming'] = 'deny' if 'deny (incoming)' in default_policy.lower() else 'allow'
        results['default_outgoing'] = 'allow' if 'allow (outgoing)' in default_policy.lower() else 'deny'
    else:
        results['default_incoming'] = 'unknown'
        results['default_outgoing'] = 'unknown'

    return results


def audit_ports():
    """
    تفحص هذه الدالة المنافذ المفتوحة على السيرفر.
    """
    results = {}

    # المنافذ الخطيرة التي يجب أن تكون مغلقة
    dangerous_ports = {
        21: "FTP - نقل الملفات غير المشفر",
        23: "Telnet - اتصال غير مشفر",
        25: "SMTP - قد يُستخدم لإرسال Spam",
        110: "POP3 - بريد غير مشفر",
        135: "RPC - هدف شائع للاختراق",
        139: "NetBIOS - هدف شائع للاختراق",
        445: "SMB - هدف شائع للاختراق",
        3389: "RDP - سطح المكتب البعيد",
        5900: "VNC - التحكم عن بعد",
    }

    open_ports = []
    dangerous_open = []

    # استخراج المنافذ المفتوحة
    ports_output = run_command("ss -tlnp | grep LISTEN")

    if ports_output:
        for line in ports_output.split('\n'):
            if 'LISTEN' in line:
                parts = line.split()
                for part in parts:
                    if ':' in part:
                        try:
                            port = int(part.split(':')[-1])
                            if port not in open_ports:
                                open_ports.append(port)
                                if port in dangerous_ports:
                                    dangerous_open.append({
                                        "port": port,
                                        "description": dangerous_ports[port]
                                    })
                        except ValueError:
                            continue

    results['open_ports'] = open_ports
    results['dangerous_ports'] = dangerous_open

    return results


def evaluate_firewall(firewall_results, ports_results):
    """
    تقيّم هذه الدالة نتائج فحص الجدار الناري والمنافذ.
    """
    findings = []

    # تقييم حالة UFW
    findings.append({
        "setting": "ufw_status",
        "description": "حالة الجدار الناري",
        "actual_value": firewall_results.get('ufw_status', 'unknown'),
        "expected_value": "active",
        "status": "✅ آمن" if firewall_results.get('ufw_status') == 'active' else "🔴 خطر",
        "risk": "لا يوجد" if firewall_results.get('ufw_status') == 'active' else "عالي",
        "remediation": "قم بتفعيل الجدار الناري: sudo ufw enable" if firewall_results.get('ufw_status') != 'active' else None
    })

    # تقييم السياسة الافتراضية
    findings.append({
        "setting": "default_incoming",
        "description": "سياسة الاتصالات الواردة",
        "actual_value": firewall_results.get('default_incoming', 'unknown'),
        "expected_value": "deny",
        "status": "✅ آمن" if firewall_results.get('default_incoming') == 'deny' else "🔴 خطر",
        "risk": "لا يوجد" if firewall_results.get('default_incoming') == 'deny' else "عالي",
        "remediation": "sudo ufw default deny incoming" if firewall_results.get('default_incoming') != 'deny' else None
    })

    # تقييم المنافذ الخطيرة
    for dangerous_port in ports_results.get('dangerous_ports', []):
        findings.append({
            "setting": f"port_{dangerous_port['port']}",
            "description": dangerous_port['description'],
            "actual_value": "مفتوح",
            "expected_value": "مغلق",
            "status": "🔴 خطر",
            "risk": "عالي",
            "remediation": f"أغلق المنفذ: sudo ufw deny {dangerous_port['port']}"
        })

    # إضافة قائمة المنافذ المفتوحة كمعلومة
    findings.append({
        "setting": "open_ports_list",
        "description": "قائمة المنافذ المفتوحة",
        "actual_value": str(ports_results.get('open_ports', [])),
        "expected_value": "منافذ ضرورية فقط",
        "status": "📋 معلومة",
        "risk": "للمراجعة",
        "remediation": None
    })

    return findings


def calculate_firewall_score(findings):
    """
    تحسب درجة أمان الجدار الناري من 100.
    """
    # تجاهل المعلومات في الحساب
    scoreable = [f for f in findings if f['risk'] != 'للمراجعة']
    total = len(scoreable)
    if total == 0:
        return 0

    secure_count = sum(1 for f in scoreable if f['risk'] == 'لا يوجد')
    return int((secure_count / total) * 100)


if __name__ == "__main__":
    print("[-] جاري فحص الجدار الناري والمنافذ...")

    firewall_results = audit_firewall()
    ports_results = audit_ports()
    findings = evaluate_firewall(firewall_results, ports_results)
    score = calculate_firewall_score(findings)

    print("\n" + "="*60)
    print("       🛡️  تقرير فحص الجدار الناري والمنافذ")
    print("="*60)

    for finding in findings:
        print(f"\n🔧 الإعداد     : {finding['setting']}")
        print(f"   الوصف       : {finding['description']}")
        print(f"   القيمة الحالية : {finding['actual_value']}")
        print(f"   القيمة المطلوبة: {finding['expected_value']}")
        print(f"   الحالة       : {finding['status']}")
        print(f"   مستوى الخطر  : {finding['risk']}")
        if finding['remediation']:
            print(f"   💡 التوصية   : {finding['remediation']}")
        print("-"*60)

    print(f"\n📊 درجة أمان الجدار الناري: {score}/100")
    print("="*60 + "\n")
