DOMAIN_WEIGHTS = {
    "ssh": 0.40,
    "firewall": 0.35,
    "users": 0.25,
}


def calculate_scores(results):
    """Return (domain_scores dict, final_weighted_score).

    domain_scores format:
        { "ssh": {"earned": N, "max": M, "percentage": P}, ... }

    Final score normalises weights to only the audited domains so partial
    audits (e.g. --audit ssh) still produce a meaningful 0-100 number.
    """
    domain_scores = {}

    for domain, checks in results.items():
        earned = sum(c["score"] for c in checks)
        maximum = sum(c["max_score"] for c in checks)
        pct = (earned / maximum * 100) if maximum > 0 else 0.0
        domain_scores[domain] = {"earned": earned, "max": maximum, "percentage": pct}

    # Normalise weights to audited domains only
    total_weight = sum(DOMAIN_WEIGHTS.get(d, 0) for d in domain_scores)
    final = 0.0
    if total_weight > 0:
        for domain, scores in domain_scores.items():
            w = DOMAIN_WEIGHTS.get(domain, 0)
            final += scores["percentage"] * (w / total_weight)

    return domain_scores, final


def score_label(score):
    if score >= 80:
        return "Good"
    elif score >= 60:
        return "Needs Improvement"
    elif score >= 40:
        return "Danger"
    else:
        return "Critical"
