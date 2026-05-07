#!/usr/bin/env python3
"""
SecureConfig Auditor — سياج
أداة تدقيق أمني لخوادم Linux مبنية على معايير CIS Benchmarks
"""

import argparse
import sys
import os

# تأكد من أن الأداة تعمل من مجلدها
sys.path.insert(0, os.path.dirname(__file__))

import ssh_audit
import firewall_audit
import users_audit
import scoring
import ui
import exporter


def parse_args():
    parser = argparse.ArgumentParser(
        description="SecureConfig Auditor — تدقيق أمني لخوادم Linux",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--audit",
        choices=["ssh", "firewall", "users", "all"],
        default="all",
        help=(
            "اختر وحدة الفحص:\n"
            "  ssh       — فحص إعدادات SSH\n"
            "  firewall  — فحص الجدار الناري\n"
            "  users     — فحص حسابات المستخدمين\n"
            "  all       — فحص شامل (افتراضي)"
        ),
    )
    parser.add_argument(
        "--output",
        choices=["cli", "json", "txt"],
        default="cli",
        help=(
            "صيغة التقرير:\n"
            "  cli   — عرض في الطرفية (افتراضي)\n"
            "  json  — تصدير JSON\n"
            "  txt   — تصدير TXT"
        ),
    )
    return parser.parse_args()


def run_modules(audit_choice):
    """تشغيل وحدات الفحص المطلوبة"""
    modules_map = {
        "ssh":      ssh_audit.run,
        "firewall": firewall_audit.run,
        "users":    users_audit.run,
    }

    if audit_choice == "all":
        selected = ["ssh", "firewall", "users"]
    else:
        selected = [audit_choice]

    results = []
    for name in selected:
        print(f"  جاري فحص {name}...", end="\r")
        result = modules_map[name]()
        results.append(result)
        print(f"  ✔ اكتمل فحص {name}          ")

    return results


def main():
    args = parse_args()

    ui.print_header()

    # تحقق من صلاحية Root
    if os.geteuid() != 0:
        print("  ⚠ تحذير: يُفضل تشغيل الأداة بـ sudo للحصول على نتائج كاملة\n")

    print("  بدء الفحص...\n")
    modules_results = run_modules(args.audit)

    summary = scoring.summarize(modules_results)

    if args.output == "cli":
        for result in modules_results:
            ui.print_module_results(result)
        ui.print_summary(summary)

    elif args.output == "json":
        path = exporter.export_json(modules_results, summary)
        ui.print_summary(summary)
        print(f"  📄 تم حفظ التقرير: {path}\n")

    elif args.output == "txt":
        path = exporter.export_txt(modules_results, summary)
        ui.print_summary(summary)
        print(f"  📄 تم حفظ التقرير: {path}\n")


if __name__ == "__main__":
    main()
