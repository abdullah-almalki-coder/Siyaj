WEIGHTS = {
    "SSH":      0.40,
    "Firewall": 0.35,
    "Users":    0.25,
}


def calculate_final_score(modules_results):
    """حساب الدرجة النهائية بالأوزان المحددة"""
    total = 0
    for result in modules_results:
        module_name = result["module"]
        weight = WEIGHTS.get(module_name, 0)
        total += result["score"] * weight
    return round(total)


def classify_score(score):
    """تصنيف الدرجة النهائية"""
    if score >= 80:
        return "جيد", "green"
    elif score >= 60:
        return "يحتاج تحسين", "yellow"
    elif score >= 40:
        return "خطر", "red"
    else:
        return "حرج", "red"


def get_top_issues(modules_results, limit=5):
    """استخراج أهم المشاكل بالأولوية"""
    all_issues = []

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    for module_result in modules_results:
        module_name = module_result["module"]
        for r in module_result["results"]:
            status = r.get("status", "")
            if status in ("خطر", "تحذير", "مفقود"):
                severity = r.get("severity", "medium")
                all_issues.append({
                    "module": module_name,
                    "check": r.get("check") or r.get("setting") or r.get("id"),
                    "detail": r.get("detail") or r.get("description"),
                    "severity": severity,
                    "recommendation": r.get("recommendation"),
                    "_order": severity_order.get(severity, 99),
                })

    all_issues.sort(key=lambda x: x["_order"])
    return all_issues[:limit]


def summarize(modules_results):
    """إنشاء ملخص شامل للنتائج"""
    final_score = calculate_final_score(modules_results)
    classification, color = classify_score(final_score)
    top_issues = get_top_issues(modules_results)

    return {
        "final_score": final_score,
        "classification": classification,
        "color": color,
        "modules": [
            {
                "name": r["module"],
                "score": r["score"],
                "weight": int(WEIGHTS.get(r["module"], 0) * 100),
            }
            for r in modules_results
        ],
        "top_issues": top_issues,
    }
