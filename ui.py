from colorama import init, Fore, Style

init(autoreset=True)

BANNER = r"""
  ███████╗██╗██╗   ██╗ █████╗      ██╗
  ██╔════╝██║╚██╗ ██╔╝██╔══██╗     ██║
  ███████╗██║ ╚████╔╝ ███████║     ██║
  ╚════██║██║  ╚██╔╝  ██╔══██║██   ██║
  ███████║██║   ██║   ██║  ██║╚█████╔╝
  ╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚════╝
"""


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + BANNER)
    print(Fore.CYAN + Style.BRIGHT + "  سياج — SecureConfig Auditor v1.0")
    print(Fore.WHITE + "  " + "=" * 47 + "\n")


def print_section(title):
    print(Fore.CYAN + Style.BRIGHT + f"\n[*] {title}")
    print(Fore.WHITE + "-" * 52)


def print_check(name, status, detail=""):
    if status == "PASS":
        tag = Fore.GREEN + Style.BRIGHT + "[PASS]"
    elif status == "FAIL":
        tag = Fore.RED + Style.BRIGHT + "[FAIL]"
    else:
        tag = Fore.YELLOW + Style.BRIGHT + "[WARN]"
    print(f"  {tag} {Fore.WHITE}{name}: {Fore.YELLOW}{detail}")


def print_score(domain, earned, maximum):
    pct = (earned / maximum * 100) if maximum > 0 else 0.0
    color = _score_color(pct)
    print(f"  {color}{domain}: {earned:.1f}/{maximum} ({pct:.1f}%)")


def print_final_score(score):
    color = _score_color(score)
    label = score_label(score)
    print(Fore.WHITE + Style.BRIGHT + "\n" + "=" * 52)
    print(Fore.WHITE + Style.BRIGHT + "  FINAL SECURITY SCORE")
    print(Fore.WHITE + Style.BRIGHT + "=" * 52)
    print(f"  {color}{Style.BRIGHT}  {score:.1f} / 100  —  {label}")
    print(Fore.WHITE + Style.BRIGHT + "=" * 52 + "\n")


def score_label(score):
    if score >= 80:
        return "Good"
    elif score >= 60:
        return "Needs Improvement"
    elif score >= 40:
        return "Danger"
    else:
        return "Critical"


def _score_color(score):
    if score >= 80:
        return Fore.GREEN
    elif score >= 60:
        return Fore.YELLOW
    elif score >= 40:
        return Fore.RED
    else:
        return Fore.RED + Style.BRIGHT
