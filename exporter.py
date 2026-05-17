import json
import datetime

from scoring import score_label


def export_json(results, domain_scores, final_score, filepath):
    data = {
        "tool": "Siyaj — SecureConfig Auditor v1.0",
        "timestamp": datetime.datetime.now().isoformat(),
        "final_score": round(final_score, 2),
        "score_label": score_label(final_score),
        "domain_scores": domain_scores,
        "results": results,
    }
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON report saved: {filepath}")
    except OSError as e:
        print(f"[ERROR] Could not write JSON report: {e}")


def export_txt(results, domain_scores, final_score, filepath):
    label = score_label(final_score)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 60,
        "  Siyaj — SecureConfig Auditor v1.0",
        f"  Generated: {ts}",
        "=" * 60,
        "",
        f"FINAL SCORE: {final_score:.1f}/100  —  {label}",
        "",
        "DOMAIN SCORES:",
    ]

    for domain, s in domain_scores.items():
        lines.append(f"  {domain.upper()}: {s['earned']}/{s['max']} ({s['percentage']:.1f}%)")

    lines.append("")

    for domain, checks in results.items():
        lines.append("=" * 60)
        lines.append(f"  {domain.upper()} AUDIT")
        lines.append("-" * 60)
        for c in checks:
            lines.append(f"  [{c['status']}] {c['check']}: {c['detail']}")
        lines.append("")

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"[+] TXT report saved:  {filepath}")
    except OSError as e:
        print(f"[ERROR] Could not write TXT report: {e}")
