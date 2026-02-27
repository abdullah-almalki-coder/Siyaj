import argparse
import sys

def print_banner():
    print("="*50)
    print("🛡️  Siyaj - Linux Security Auditor")
    print("="*50)

def main():
    # إعداد واجهة سطر الأوامر
    parser = argparse.ArgumentParser(description="Siyaj: Smart Security Auditor for Linux Servers")
    
    # إضافة الخيارات (Arguments)
    parser.add_argument('--audit', choices=['all', 'ssh', 'users', 'firewall'], help='Specify the module to audit')
    parser.add_argument('--export', type=str, help='Export report to a specific file (e.g., report.json or report.txt)')

    args = parser.parse_args()

    print_banner()

    # التحقق من إدخال أمر الفحص
    if not args.audit:
        print("❌ خطأ: يرجى تحديد نوع الفحص.")
        print("💡 جرب استخدام: python3 main.py --audit all")
        sys.exit(1)

    # توجيه الأوامر (سيتم ربطها بملفات الزملاء لاحقاً)
    if args.audit == 'all':
        print("[+] بدء الفحص الشامل للنظام...")
        # سيتم استدعاء دوال الفحص الشامل هنا
    elif args.audit == 'ssh':
        print("[+] جاري قراءة وتحليل إعدادات SSH...")
        # استدعاء دالة sshd_auditor.py
    elif args.audit == 'users':
        print("[+] جاري فحص حسابات المستخدمين وصلاحيات الـ Root...")
        # استدعاء دالة user_auditor.py
    elif args.audit == 'firewall':
        print("[+] جاري فحص الجدار الناري والمنافذ المفتوحة...")
        # استدعاء دالة firewall_auditor.py

    # التحقق من طلب تصدير التقرير
    if args.export:
        print(f"[+] سيتم تصدير نتيجة الفحص إلى الملف: {args.export}")

if __name__ == "__main__":
    main()
