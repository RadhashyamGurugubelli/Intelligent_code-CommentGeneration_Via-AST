def summarize_scores(scores):
    """Return a summary of scores, including the three highest values."""
    numeric_scores = [
        score for score in scores
        if isinstance(score, (int, float))
    ]
    if not numeric_scores:
        return {
            "count": 0,
            "average": 0.0,
            "highest": None,
            "top_three": [],
        }

    ordered_scores = sorted(numeric_scores, reverse=True)
    return {
        "count": len(numeric_scores),
        "average": round(sum(numeric_scores) / len(numeric_scores), 2),
        "highest": ordered_scores[0],
        "top_three": ordered_scores[:3],
    }
