"""Timetable support: spot schedule emails and flag clashing / revised exam dates.

TRIAGE cannot know which timetable is the official one - it only points out the
difference so the student can verify with the examination office.
"""
from __future__ import annotations

import re
from datetime import date

from . import config
from .dates import extract_dates
from .models import Email, Result
from .rules import find_terms

COURSE_RE = re.compile(r"\b[A-Z]{2,4}[- ]?\d{3,4}\b")
CLEAN_RE = re.compile(r"[^a-z ]+")


def is_timetable_email(email: Email) -> bool:
    text = f"{email.subject}\n{email.body}"
    return bool(find_terms(text, config.EXAM_TERMS)) and bool(find_terms(text, config.SCHEDULE_TERMS))


def extract_entries(email: Email, today: date) -> dict[str, date]:
    """Map a course key (course code, else cleaned line text) to its exam date."""
    ref = email.date.date() if email.date else today
    entries: dict[str, date] = {}
    for line in f"{email.subject}\n{email.body}".splitlines():
        dates = extract_dates(line, ref)
        # only absolute dates make sense for a timetable entry
        dates = [(d, s) for d, s in dates if re.search(r"\d", s)]
        if not dates:
            continue
        m = COURSE_RE.search(line)
        if m:
            key = re.sub(r"[- ]", "", m.group(0))
        else:
            cleaned = line
            for _, s in dates:
                cleaned = cleaned.replace(s, " ")
            key = " ".join(w for w in CLEAN_RE.sub(" ", cleaned.lower()).split() if len(w) > 2)
            if not key:
                continue
        entries[key] = dates[0][0]
    return entries


def apply_timetable_checks(results: list[Result], today: date) -> None:
    """Mutates results in place: sets .timetable and .timetable_notes."""
    tt = [r for r in results if is_timetable_email(r.email)]
    for r in tt:
        r.timetable = "Timetable email"
        if find_terms(f"{r.email.subject}\n{r.email.body}", config.REVISION_TERMS):
            r.timetable = "Revised notice"
            r.timetable_notes.append("This email says the schedule was revised or rescheduled.")

    seen: dict[str, list[tuple[Result, date]]] = {}
    for r in tt:
        for key, when in extract_entries(r.email, today).items():
            seen.setdefault(key, []).append((r, when))

    for key, items in seen.items():
        if len({w for _, w in items}) < 2 or len({id(r) for r, _ in items}) < 2:
            continue
        summary = "; ".join(f"{r.email.id}: {w.strftime('%d %b %Y')}" for r, w in items)
        for r, _ in items:
            r.timetable = "Possible conflict"
            r.timetable_notes.append(
                f"'{key}' has different dates across emails ({summary}). "
                "TRIAGE cannot tell which is official - confirm with the examination office."
            )
