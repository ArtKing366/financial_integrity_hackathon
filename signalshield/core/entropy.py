import math
from collections import Counter

from core.domain_utils import split_domain

DEFAULT_ENTROPY_THRESHOLD = 3.8
HIGH_ENTROPY_SCORE = 50


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def extract_domain_core(url_or_domain: str) -> str:
    return split_domain(url_or_domain)["domain"].lower()


def check_domain_entropy(
    url_or_domain: str,
    threshold: float = DEFAULT_ENTROPY_THRESHOLD,
) -> dict:
    core = extract_domain_core(url_or_domain)
    entropy = shannon_entropy(core)
    flagged = entropy > threshold

    result = {
        "domain_core": core,
        "entropy": round(entropy, 2),
        "threshold": threshold,
        "flagged": flagged,
        "score": 0,
        "description": "",
    }

    if not core:
        return result

    if flagged:
        result["score"] = HIGH_ENTROPY_SCORE
        result["description"] = (
            f"Domain name '{core}' has high Shannon entropy ({entropy:.2f}), "
            "indicating likely machine-generated randomness."
        )

    return result
