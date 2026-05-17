#!/usr/bin/env python3
"""Siyaj — SecureConfig Auditor v1.0

Usage:
    sudo python3 main.py --audit all
    sudo python3 main.py --audit ssh
    sudo python3 main.py --audit firewall
    sudo python3 main.py --audit users
    sudo python3 main.py --audit all --output json
    sudo python3 main.py --audit all --output txt
"""

import argparse
import datetime
import json
import os
import sys

from exporter import export_json, export_txt
from firewall_audit import audit_firewall
from scoring import calculate_scores
from ssh_audit import audit_ssh
from ui import print_banner, print_check, print_final_score, print_score, print_section
from users_audit import audit_users

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CIS_RULES_PATH = os.path.join(SCRIPT_DIR, "cis_rules.json")


def load_rules():
    try:
        with open(CIS_RULES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Rule database not found: {CIS_RULES_PATH}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in cis_rules.json: {e}")
        sys.exit(1)


def run_audit(audit_type, rules, output_format=None):
    results = {}

    if audit_type in ("all", "ssh"):
        print_section("SSH Audit  (/etc/ssh/sshd_config)")
        results["ssh"] = audit_ssh(rules)
        for c in results["ssh"]:
            print_check(c["check"], c["status"], c["detail"])

    if audit_type in ("all", "firewall"):
        print_section("Firewall Audit  (UFW)")
        results["firewall"] = audit_firewall(rules)
        for c in results["firewall"]:
            print_check(c["check"], c["status"], c["detail"])

    if audit_type in ("all", "users"):
        print_section("Users Audit  (/etc/passwd  /etc/shadow  sudoers)")
        results["users"] = audit_users(rules)
        for c in results["users"]:
            print_check(c["check"], c["status"], c["detail"])

    domain_scores, final_score = calculate_scores(results)

    print_section("Score Summary")
    for domain, s in domain_scores.items():
        print_score(domain.upper(), s["earned"], s["max"])

    print_final_score(final_score)

    if output_format:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(SCRIPT_DIR, f"siyaj_report_{ts}.{output_format}")
        if output_format == "json":
            export_json(results, domain_scores, final_score, report_path)
        else:
            export_txt(results, domain_scores, final_score, report_path)

    return final_score


def main():
    if os.geteuid() != 0:
        print("[ERROR] This tool must be run as root: sudo python3 main.py")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        prog="siyaj",
        description="Siyaj — SecureConfig Auditor v1.0  |  سياج",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--audit",
        choices=["all", "ssh", "firewall", "users"],
        required=True,
        metavar="DOMAIN",
        help="Audit domain: all | ssh | firewall | users",
    )
    parser.add_argument(
        "--output",
        choices=["json", "txt"],
        metavar="FORMAT",
        help="Export report format: json | txt",
    )

    args = parser.parse_args()

    print_banner()
    rules = load_rules()
    score = run_audit(args.audit, rules, args.output)
    sys.exit(0 if score >= 60 else 1)


if __name__ == "__main__":
    main()
