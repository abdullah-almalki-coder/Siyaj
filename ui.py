from colorama import init, Fore, Back, Style

# تهيئة colorama
init(autoreset=True)


def print_header():
    """
    تطبع رأس الأداة.
    """
    print(Fore.CYAN + Style.BRIGHT + "\n" + "="*60)
    print(Fore.CYAN + Style.BRIGHT + "       🛡️  SecureConfig Auditor v1.0")
    print(Fore.CYAN + Style.BRIGHT + "       نظام تدقيق أمني لخوادم Linux")
    print(Fore.CYAN + Style.BRIGHT + "="*60 + Style.RESET_ALL)


def print_module_header(module_name):
    """
    تطبع عنوان كل وحدة فحص.
    """
    print(Fore.YELLOW + Style.BRIGHT + f"\n[ فحص {module_name} ]")
    print(Fore.YELLOW + "-"*60 + Style.RESET_ALL)


def print_finding(finding):
    """
    تطبع نتيجة فحص واحدة بألوان مناسبة.
    """
    risk = finding.get('risk', '')

    # تحديد لون السطر بناءً على مستوى الخطر
    if risk == 'لا يوجد':
        color = Fore.GREEN
        icon = "✅"
    elif risk == 'عالي':
        color = Fore.RED
        icon = "🔴"
    elif risk == 'حرج':
        color = Fore.RED + Style.BRIGHT
        icon = "🚨"
    elif risk == 'متوسط':
        color = Fore.YELLOW
        icon = "⚠️ "
    else:
        color = Fore.BLUE
        icon = "📋"

    print(f"\n{color}{icon} الإعداد     : {finding['setting']}{Style.RESET_ALL}")
    print(f"   الوصف       : {finding['description']}")
    print(f"   القيمة الحالية : {color}{finding['actual_value']}{Style.RESET_ALL}")
    print(f"   القيمة المطلوبة: {Fore.GREEN}{finding['expected_value']}{Style.RESET_ALL}")
    print(f"   الحالة       : {finding['status']}")
    print(f"   مستوى الخطر  : {color}{finding['risk']}{Style.RESET_ALL}")

    if finding.get('remediation'):
        print(f"   {Fore.CYAN}💡 التوصية   : {finding['remediation']}{Style.RESET_ALL}")

    print(Fore.WHITE + "   " + "-"*56 + Style.RESET_ALL)


def print_score_bar(module_name, score):
    """
    تطبع شريط الدرجة الملون.
    """
    filled = score // 10
    empty = 10 - filled

    if score >= 80:
        color = Fore.GREEN
    elif score >= 60:
        color = Fore.YELLOW
    elif score >= 40:
        color = Fore.RED
    else:
        color = Fore.RED + Style.BRIGHT

    bar = color + "█" * filled + Fore.WHITE + "░" * empty + Style.RESET_ALL
    print(f"  {module_name:<20} [{bar}] {color}{score}/100{Style.RESET_ALL}")


def print_final_summary(scores, final_score):
    """
    تطبع الملخص النهائي الملون.
    """
    print(Fore.CYAN + Style.BRIGHT + "\n" + "="*60)
    print(Fore.CYAN + Style.BRIGHT + "       📊 الملخص النهائي")
    print(Fore.CYAN + Style.BRIGHT + "="*60 + Style.RESET_ALL)

    print("\n  درجات الوحدات:")
    module_names = {
        'ssh': 'SSH',
        'firewall': 'الجدار الناري',
        'users': 'المستخدمون'
    }

    for module, score in scores.items():
        name = module_names.get(module, module)
        print_score_bar(name, score)

    # الدرجة النهائية
    if final_score >= 80:
        final_color = Fore.GREEN
        status = "✅ جيد"
    elif final_score >= 60:
        final_color = Fore.YELLOW
        status = "⚠️  يحتاج تحسين"
    elif final_score >= 40:
        final_color = Fore.RED
        status = "🔴 خطر"
    else:
        final_color = Fore.RED + Style.BRIGHT
        status = "🚨 حرج"

    print(Fore.CYAN + "\n" + "="*60)
    print(f"  📊 الدرجة النهائية: {final_color}{Style.BRIGHT}{final_score}/100{Style.RESET_ALL}")
    print(f"  الوضع الأمني     : {final_color}{Style.BRIGHT}{status}{Style.RESET_ALL}")
    print(Fore.CYAN + "="*60 + Style.RESET_ALL + "\n")


def print_priority_issues(critical_issues, high_issues):
    """
    تطبع المشاكل الأولوية بألوان واضحة.
    """
    if critical_issues:
        print(Fore.RED + Style.BRIGHT + "\n🚨 مشاكل حرجة يجب معالجتها فوراً:")
        print("-"*60 + Style.RESET_ALL)
        for issue in critical_issues:
            print(Fore.RED + f"  ❌ [{issue['module'].upper()}] {issue['description']}" + Style.RESET_ALL)
            if issue.get('remediation'):
                print(Fore.CYAN + f"     💡 {issue['remediation']}" + Style.RESET_ALL)

    if high_issues:
        print(Fore.YELLOW + Style.BRIGHT + "\n🔴 مشاكل عالية الخطورة:")
        print("-"*60 + Style.RESET_ALL)
        for issue in high_issues:
            print(Fore.YELLOW + f"  ⚠️  [{issue['module'].upper()}] {issue['description']}" + Style.RESET_ALL)
            if issue.get('remediation'):
                print(Fore.CYAN + f"     💡 {issue['remediation']}" + Style.RESET_ALL)


def print_progress(message):
    """
    تطبع رسالة تقدم أثناء الفحص.
    """
    print(Fore.CYAN + f"[*] {message}..." + Style.RESET_ALL)


def print_error(message):
    """
    تطبع رسالة خطأ.
    """
    print(Fore.RED + Style.BRIGHT + f"[!] خطأ: {message}" + Style.RESET_ALL)


def print_success(message):
    """
    تطبع رسالة نجاح.
    """
    print(Fore.GREEN + f"[✓] {message}" + Style.RESET_ALL)
