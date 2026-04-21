import argparse
import json
import datetime
import os
from ssh_audit import audit_ssh, evaluate_ssh, calculate_score, print_report

def parse_arguments():
    """
    تستقبل هذه الدالة أوامر المستخدم من الطرفية.
    """
    parser = argparse.ArgumentParser(
        description='🛡️  SecureConfig Auditor - أداة تدقيق أمني لخوادم Linux',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '--audit',
        choices=['ssh', 'firewall', 'users', 'all'],
        default='all',
        help='نوع الفحص:\n  ssh      = فحص إعدادات SSH\n  firewall = فحص الجدار الناري\n  users    = فحص المستخدمين\n  all      = فحص شامل (افتراضي)'
    )
    
    parser.add_argument(
        '--output',
        choices=['cli', 'json', 'txt'],
        default='cli',
        help='صيغة التقرير:\n  cli  = عرض في الطرفية (افتراضي)\n  json = حفظ كملف JSON\n  txt  = حفظ كملف TXT'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Siyaj'
    )
    
    return parser.parse_args()


def run_audit(audit_type):
    """
    تشغل هذه الدالة الفحص المطلوب وتجمع النتائج.
    """
    all_findings = []
    total_score = 0
    modules_run = 0

    if audit_type in ['ssh', 'all']:
        print("\n[*] جاري فحص إعدادات SSH...")
        raw = audit_ssh()
        if "error" in raw:
            print(f"[!] خطأ في فحص SSH: {raw['error']}")
        else:
            findings = evaluate_ssh(raw)
            score = calculate_score(findings)
            all_findings.append({
                "module": "SSH",
                "findings": findings,
                "score": score
            })
            total_score += score
            modules_run += 1

    if audit_type in ['firewall', 'all']:
        print("\n[*] جاري فحص الجدار الناري...")
        # سيتم ربطه لاحقاً مع firewall_audit.py
        print("[~] وحدة الجدار الناري قيد التطوير...")

    if audit_type in ['users', 'all']:
        print("\n[*] جاري فحص حسابات المستخدمين...")
        # سيتم ربطه لاحقاً مع users_audit.py
        print("[~] وحدة المستخدمين قيد التطوير...")

    final_score = int(total_score / modules_run) if modules_run > 0 else 0
    return all_findings, final_score


def export_report(all_findings, final_score, output_format):
    """
    تصدر هذه الدالة التقرير بالصيغة المطلوبة.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    if output_format == 'json':
        filename = f"report_{timestamp}.json"
        report_data = {
            "timestamp": timestamp,
            "final_score": final_score,
            "modules": all_findings
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=4)
        print(f"\n✅ تم حفظ التقرير: {filename}")

    elif output_format == 'txt':
        filename = f"report_{timestamp}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("🛡️  SecureConfig Auditor - تقرير الفحص الأمني\n")
            f.write(f"التاريخ: {timestamp}\n")
            f.write(f"الدرجة النهائية: {final_score}/100\n")
            f.write("="*60 + "\n\n")
            for module in all_findings:
                f.write(f"\n[ وحدة: {module['module']} ] - الدرجة: {module['score']}/100\n")
                f.write("-"*60 + "\n")
                for finding in module['findings']:
                    f.write(f"الإعداد    : {finding['setting']}\n")
                    f.write(f"الحالة     : {finding['status']}\n")
                    f.write(f"القيمة الحالية: {finding['actual_value']}\n")
                    if finding['remediation']:
                        f.write(f"التوصية    : {finding['remediation']}\n")
                    f.write("\n")
        print(f"\n✅ تم حفظ التقرير: {filename}")


def print_final_summary(all_findings, final_score):
    """
    تطبع ملخصاً نهائياً شاملاً في الطرفية.
    """
    print("\n" + "="*60)
    print("       🛡️  SecureConfig Auditor - الملخص النهائي")
    print("="*60)

    for module in all_findings:
        print_report(module['findings'], module['score'])

    print("\n" + "="*60)
    print(f"  📊 الدرجة النهائية الشاملة: {final_score}/100")

    if final_score >= 80:
        print("  ✅ الوضع الأمني العام: جيد")
    elif final_score >= 50:
        print("  ⚠️  الوضع الأمني العام: يحتاج تحسين")
    else:
        print("  🔴 الوضع الأمني العام: حرج - يجب المعالجة فوراً")

    print("="*60 + "\n")


if __name__ == "__main__":
    print("="*60)
    print("  🛡️  SecureConfig Auditor v1.0")
    print("  نظام تدقيق أمني لخوادم Linux")
    print("="*60)

    args = parse_arguments()
    all_findings, final_score = run_audit(args.audit)

    if args.output == 'cli':
        print_final_summary(all_findings, final_score)
    else:
        export_report(all_findings, final_score, args.output)
