import json
import os
from datetime import datetime


def _get_output_path(fmt):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"siyaj_report_{timestamp}.{fmt}"
    return filename


def export_json(modules_results, summary):
    """تصدير التقرير بصيغة JSON"""
    report = {
        "tool": "SecureConfig Auditor — سياج",
        "generated_at": datetime.now().isoformat(),
        "summary": summary,
        "modules": modules_results,
    }
    path = _get_output_path("json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return path


def export_txt(modules_results, summary):
    """تصدير التقرير بصيغة TXT"""
    lines = []
    sep = "═" * 55

    lines.append(sep)
    lines.append("SecureConfig Auditor — نظام تدقيق أمني Linux")
    lines.append(f"تاريخ الفحص: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(sep)
    lines.append("")

    score = summary["final_score"]
    classification = summary["classification"]
    lines.append(f"النتيجة النهائية: {score}/100 — {classification}")
    lines.append("")

    lines.append("الأوزان:")
    for m in summary["modules"]:
        lines.append(f"  {m['name']:10} {m['score']:3}/100  ({m['weight']}%)")
    lines.append("")

    if summary["top_issues"]:
        lines.append("أهم المشاكل:")
        for i, issue in enumerate(summary["top_issues"], 1):
            lines.append(f"  {i}. [{issue['module']}] {issue['check']}")
            if issue["recommendation"]:
                lines.append(f"     → {issue['recommendation']}")
        lines.append("")

    for module_result in modules_results:
        lines.append(sep)
        lines.append(f"وحدة {module_result['module']} — {module_result['score']}/100")
        lines.append("")
        for r in module_result["results"]:
            status = r.get("status", "")
            check = r.get("check") or r.get("setting") or ""
            detail = r.get("detail") or r.get("description") or ""
            recommendation = r.get("recommendation")
            lines.append(f"  [{status}] {check}")
            if detail:
                lines.append(f"       {detail}")
            if recommendation:
                lines.append(f"       → {recommendation}")
            lines.append("")

    lines.append(sep)

    path = _get_output_path("txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path
