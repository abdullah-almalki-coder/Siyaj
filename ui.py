try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = ""

    class Style:
        BRIGHT = RESET_ALL = ""


def color(text, clr):
    if not HAS_COLOR:
        return text
    colors = {
        "green":   Fore.GREEN,
        "red":     Fore.RED,
        "yellow":  Fore.YELLOW,
        "cyan":    Fore.CYAN,
        "white":   Fore.WHITE,
        "magenta": Fore.MAGENTA,
    }
    return f"{colors.get(clr, '')}{Style.BRIGHT}{text}{Style.RESET_ALL}"


def print_header():
    print("\n" + color("═" * 55, "cyan"))
    print(color("   SecureConfig Auditor — نظام تدقيق أمني Linux", "cyan"))
    print(color("═" * 55, "cyan") + "\n")


def score_bar(score, width=30):
    filled = int((score / 100) * width)
    bar = "█" * filled + "░" * (width - filled)
    if score >= 80:
        return color(f"[{bar}]", "green")
    elif score >= 60:
        return color(f"[{bar}]", "yellow")
    else:
        return color(f"[{bar}]", "red")


def status_badge(status):
    badges = {
        "آمن":    color("✔ آمن", "green"),
        "خطر":    color("✘ خطر", "red"),
        "مفقود":  color("? مفقود", "yellow"),
        "تحذير":  color("⚠ تحذير", "yellow"),
    }
    return badges.get(status, status)


def print_module_results(module_result):
    name = module_result["module"]
    score = module_result["score"]
    results = module_result["results"]

    print(color(f"\n── وحدة {name} ──────────────────────────────", "magenta"))
    print(f"  الدرجة: {score}/100  {score_bar(score)}")
    print()

    for r in results:
        status = r.get("status", "")
        check = r.get("check") or r.get("setting") or ""
        detail = r.get("detail") or r.get("description") or ""
        recommendation = r.get("recommendation")

        print(f"  {status_badge(status)}  {check}")
        if detail:
            print(f"         {color(detail, 'white')}")
        if recommendation:
            print(f"         {color('→ ' + recommendation, 'yellow')}")
        print()


def print_summary(summary):
    score = summary["final_score"]
    classification = summary["classification"]
    clr = summary["color"]

    print(color("═" * 55, "cyan"))
    print(color(f"  النتيجة النهائية: {score}/100 — {classification}", clr))
    print(f"  {score_bar(score, width=40)}")
    print()

    print("  الأوزان:")
    for m in summary["modules"]:
        bar = score_bar(m["score"], width=20)
        print(f"    {m['name']:10} {m['score']:3}/100  {bar}  ({m['weight']}%)")

    print()
    if summary["top_issues"]:
        print(color("  ⚠ أهم المشاكل التي تحتاج معالجة:", "red"))
        for i, issue in enumerate(summary["top_issues"], 1):
            print(f"    {i}. [{issue['module']}] {issue['check']}")
            if issue["recommendation"]:
                print(f"       {color('→ ' + issue['recommendation'], 'yellow')}")
    else:
        print(color("  ✔ الخادم في حالة أمنية ممتازة!", "green"))

    print(color("═" * 55, "cyan") + "\n")
