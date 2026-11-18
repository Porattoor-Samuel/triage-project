"""Mailbox report summaries for uploaded email collections."""
from __future__ import annotations

from collections import Counter
from datetime import date, timedelta
from email.utils import parseaddr
from typing import Iterable

from .models import Email


def received_period_counts(emails: Iterable[Email], reference: date) -> dict[str, int]:
    """Count dated messages in the reference day, Monday-based week, month, and year."""
    week_start = reference - timedelta(days=reference.weekday())
    starts = {
        "Today": reference,
        "This week": week_start,
        "This month": reference.replace(day=1),
        "This year": reference.replace(month=1, day=1),
    }
    counts = dict.fromkeys(starts, 0)
    for email in emails:
        if email.date is None:
            continue
        received = email.date.date()
        if received > reference:
            continue
        for label, start in starts.items():
            if received >= start:
                counts[label] += 1
    return counts


def sender_rankings(emails: Iterable[Email]) -> list[dict[str, int | str]]:
    """Rank senders by message count, grouping addresses case-insensitively."""
    labels: dict[str, str] = {}
    counts: Counter[str] = Counter()
    for email in emails:
        name, address = parseaddr(email.sender)
        sender = address.strip().lower() or name.strip().lower() or "unknown sender"
        labels.setdefault(sender, address.strip() or name.strip() or "Unknown sender")
        counts[sender] += 1

    ordered = sorted(counts, key=lambda sender: (-counts[sender], sender))
    rankings = []
    previous_count = None
    rank = 0
    for index, sender in enumerate(ordered, start=1):
        count = counts[sender]
        if count != previous_count:
            rank = index
            previous_count = count
        rankings.append({"Rank": rank, "Sender": labels[sender], "Emails": count})
    return rankings
