"""RESULT: runs every rule set on every email and attaches a short reason."""
from __future__ import annotations

from datetime import date
from typing import Iterable

from .models import Email, Result
from .priority import analyze_priority
from .threat import analyze_threat
from .timetable import apply_timetable_checks
from .topic import analyze_topic


def analyze_email(email: Email, today: date | None = None, trusted_domains: list[str] | None = None) -> Result:
    threat, t_score, t_ev = analyze_threat(email, trusted_domains)
    priority, p_score, p_ev = analyze_priority(email, today, threat)
    topic, topic_ev = analyze_topic(email)
    return Result(
        email=email,
        threat=threat, threat_score=t_score, threat_evidence=t_ev,
        priority=priority, priority_score=p_score, priority_evidence=p_ev,
        topic=topic, topic_evidence=topic_ev,
    )


def analyze_all(emails: Iterable[Email], today: date | None = None, trusted_domains: list[str] | None = None) -> list[Result]:
    today = today or date.today()
    results = [analyze_email(e, today, trusted_domains) for e in emails]
    apply_timetable_checks(results, today)  # needs the whole batch to compare emails
    return results
