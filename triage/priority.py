"""PRIORITY: how soon should the student look at it?  High / Normal / Low."""
from __future__ import annotations

from datetime import date

from . import config
from .dates import days_until_nearest
from .models import Email, Evidence
from .rules import find_terms


def analyze_priority(email: Email, today: date | None = None, threat: str = "") -> tuple[str, int, list[Evidence]]:
    ref = email.date.date() if email.date else (today or date.today())
    text = f"{email.subject}\n{email.body}"
    ev: list[Evidence] = []

    high = find_terms(text, config.HIGH_PRIORITY_WORDS)
    if high:
        ev.append(Evidence(f"Important keyword: {high[0]!r}", ", ".join(high[:4]), 2))
    urgent = find_terms(text, config.URGENCY_PRIORITY_WORDS)
    if urgent:
        ev.append(Evidence(f"Urgency keyword: {urgent[0]!r}", ", ".join(urgent[:4]), 1))

    nearest = days_until_nearest(text, ref)
    if nearest is not None:
        days, snippet = nearest
        strong = bool(high or urgent)
        if days <= 2:
            ev.append(Evidence(f"Date is very near ({snippet!r}, {days} day(s))", snippet, 3 if strong else 1))
        elif days <= 7:
            ev.append(Evidence(f"Date within a week ({snippet!r})", snippet, 1))

    if threat == "Suspicious":
        ev.append(Evidence("Flagged as suspicious - review promptly", "threat label", 3))

    low = find_terms(text, config.LOW_PRIORITY_WORDS)
    if low:
        ev.append(Evidence(f"Low-importance keyword: {low[0]!r}", ", ".join(low[:4]), -2))

    score = sum(e.weight for e in ev)
    if score >= config.PRIORITY_HIGH:
        label = "High"
    elif score <= config.PRIORITY_LOW:
        label = "Low"
    else:
        label = "Normal"
    ev.sort(key=lambda e: -abs(e.weight))
    return label, score, ev
