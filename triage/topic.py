"""TOPIC: what is the email about?"""
from __future__ import annotations

from . import config
from .models import Email, Evidence
from .rules import find_terms


def analyze_topic(email: Email) -> tuple[str, list[Evidence]]:
    scores: dict[str, int] = {}
    evidence: dict[str, list[Evidence]] = {}
    for topic, terms in config.TOPICS.items():
        subj_hits = find_terms(email.subject, terms)
        body_hits = [h for h in find_terms(email.body, terms) if h.lower() not in {s.lower() for s in subj_hits}]
        score = 2 * len(subj_hits) + len(body_hits)  # subject words count double
        if score >= config.TOPIC_MIN_SCORE:
            scores[topic] = score
            evidence[topic] = [Evidence(f"Topic keyword: {h!r}", topic, 2 if h in subj_hits else 1) for h in subj_hits + body_hits]
    if not scores:
        return "Other", []
    order = list(config.TOPICS)  # tie-break: order in config
    best = max(scores, key=lambda t: (scores[t], -order.index(t)))
    return best, evidence[best]
