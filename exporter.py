import json
import os
import datetime


def get_timestamp():
    """
    ترجع الوقت الحالي بصيغة مناسبة لاسم الملف.
    """
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def export_json(all_findings, scores, final_score):
    """
    تصدر التقرير كملف JSON.
    """
    timestamp = get_timestamp()
    filename = f"report_{timestamp}.json"

    report = {
        "tool": "SecureConfig Auditor v1.0",
        "timestamp": timestamp,
        "final_score": final_score,
        "scores": scores,
        "modules": {}
    }

    for module_name, findings in all_findings.items():
        report["modules"][module_name] = {
            "score": scores.get(module_name, 0),
            "findings": findings
        }

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=4)

    return filename


def export_txt(all_findings, scores, final_score):
    """
    تصدر التقرير كملف TXT.
    """
    timestamp = get_timestamp()
    filename = f"report_{timestamp}.txt"

    module_names = {
        'ssh': 'SSH',
        'firewall': 'الجدار الناري',
        'users': 'المستخدمون'
    }

    with open(filename, 'w', encoding='utf-8') as f:

        # الرأس
        f.write("="*60 + "\n")
        f.write("       SecureConfig Auditor v1.0\n")
        f.write("       نظام تدقيق أمني لخوادم Linux\n")
        f.write("="*60 + "\n")
        f.write(f"التاريخ والوقت : {timestamp}\n")
        f.write(f"الدرجة النهائية: {final_score}/100\n")

        if final_score >= 80:
            f.write("الوضع الأمني   : جيد\n")
        elif final_score >= 60:
            f.write("الوضع الأمني   : يحتاج تحسين\n")
        elif final_score >= 40:
            f.write("الوضع الأمني   : خطر\n")
        else:
            f.write("الوضع الأمني   : حرج\n")

        f.write("="*60 + "\n")

        # درجات الوحدات
        f.write("\nدرجات الوحدات:\n")
        f.write("-"*60 + "\n")
        for module, score in scores.items():
            name = module_names.get(module, module)
            f.write(f"  {name:<20} {score}/100\n")

        # تفاصيل كل وحدة
        for module_name, findings in all_findings.items():
            name = module_names.get(module_name, module_name)
            f.write(f"\n{'='*60}\n")
            f.write(f"  وحدة: {name} - الدرجة: {scores.get(module_name, 0)}/100\n")
            f.write(f"{'='*60}\n")

            for finding in findings:
                f.write(f"\nالإعداد        : {finding['setting']}\n")
                f.write(f"الوصف          : {finding['description']}\n")
                f.write(f"القيمة الحالية  : {finding['actual_value']}\n")
                f.write(f"القيمة المطلوبة : {finding['expected_value']}\n")
                f.write(f"الحالة          : {finding['status']}\n")
                f.write(f"مستوى الخطر     : {finding['risk']}\n")
                if finding.get('remediation'):
                    f.write(f"التوصية         : {finding['remediation']}\n")
                f.write("-"*60 + "\n")

    return filename


def export_report(all_findings, scores, final_score, output_format):
    """
    تصدر التقرير بالصيغة المطلوبة.
    """
    if output_format == 'json':
        filename = export_json(all_findings, scores, final_score)
    elif output_format == 'txt':
        filename = export_txt(all_findings, scores, final_score)
    else:
        return None

    return filename


if __name__ == "__main__":
    # بيانات تجريبية للاختبار
    test_findings = {
        'ssh': [
            {
                "setting": "PermitRootLogin",
                "description": "منع تسجيل الدخول كـ Root",
                "actual_value": "yes",
                "expected_value": "no",
                "status": "🔴 خطر",
                "risk": "عالي",
                "remediation": "PermitRootLogin no"
            }
        ]
    }
    test_scores = {'ssh': 60, 'firewall': 80, 'users': 70}
    test_final = 70

    json_file = export_json(test_findings, test_scores, test_final)
    print(f"✅ تم حفظ: {json_file}")

    txt_file = export_txt(test_findings, test_scores, test_final)
    print(f"✅ تم حفظ: {txt_file}")
