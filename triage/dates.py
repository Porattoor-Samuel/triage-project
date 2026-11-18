"""Small, dependency-free date extraction (Indian day-first formats supported)."""
from __future__ import annotations

import math
import re
from datetime import date, datetime, timedelta
from typing import Optional

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8,
    "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}
_MON = r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
_WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]

_ISO = re.compile(r"\b(\d{4})-(\d{1,2})-(\d{1,2})\b")
_DMY = re.compile(r"\b(\d{1,2})[/-](\d{1,2})[/-](\d{4})\b")
_D_MON = re.compile(rf"\b(\d{{1,2}})(?:st|nd|rd|th)?\s+{_MON}\b\.?(?:,?\s+(\d{{4}}))?", re.I)
_MON_D = re.compile(rf"\b{_MON}\b\.?\s+(\d{{1,2}})(?:st|nd|rd|th)?\b(?:,?\s+(\d{{4}}))?", re.I)
_REL_UNIT = re.compile(r"\b(?:within|in|next)\s+(\d+)\s*(hours?|hrs?|days?)\b", re.I)
_TODAY = re.compile(r"\b(today|tonight)\b", re.I)
_TOMORROW = re.compile(r"\btomorrow\b", re.I)
_NEXT_WEEK = re.compile(r"\bnext week\b", re.I)
_WEEKDAY = re.compile(r"\b(?:on\s+|this\s+|by\s+)?(" + "|".join(_WEEKDAYS) + r")\b", re.I)


def _safe(y: int, m: int, d: int) -> Optional[date]:
    try:
        return date(y, m, d)
    except ValueError:
        return None


def _fix_year(m: int, d: int, year: Optional[str], ref: date) -> Optional[date]:
    if year:
        return _safe(int(year), m, d)
    cand = _safe(ref.year, m, d)
    if cand and cand < ref - timedelta(days=30):
        cand = _safe(ref.year + 1, m, d)
    return cand


def extract_dates(text: str, ref: date) -> list[tuple[date, str]]:
    """Return [(date, matched_text)] for absolute and relative dates found in *text*."""
    found: list[tuple[date, str]] = []
    for m in _ISO.finditer(text):
        d = _safe(int(m[1]), int(m[2]), int(m[3]))
        if d:
            found.append((d, m[0]))
    for m in _DMY.finditer(text):
        d = _safe(int(m[3]), int(m[2]), int(m[1]))
        if d:
            found.append((d, m[0]))
    for m in _D_MON.finditer(text):
        d = _fix_year(_MONTHS[m[2][:3].lower()], int(m[1]), m[3], ref)
        if d:
            found.append((d, m[0].strip()))
    for m in _MON_D.finditer(text):
        d = _fix_year(_MONTHS[m[1][:3].lower()], int(m[2]), m[3], ref)
        if d:
            found.append((d, m[0].strip()))
    for m in _TODAY.finditer(text):
        found.append((ref, m[0]))
    for m in _TOMORROW.finditer(text):
        found.append((ref + timedelta(days=1), m[0]))
    for m in _NEXT_WEEK.finditer(text):
        found.append((ref + timedelta(days=7), m[0]))
    for m in _REL_UNIT.finditer(text):
        n = int(m[1])
        days = math.ceil(n / 24) if m[2].lower().startswith("h") else n
        found.append((ref + timedelta(days=days), m[0]))
    for m in _WEEKDAY.finditer(text):
        target = _WEEKDAYS.index(m[1].lower())
        found.append((ref + timedelta(days=(target - ref.weekday()) % 7), m[0].strip()))
    return found


def days_until_nearest(text: str, ref: date) -> Optional[tuple[int, str]]:
    """Days from *ref* to the nearest upcoming (or today) date mentioned, with the matched text."""
    upcoming = [((d - ref).days, s) for d, s in extract_dates(text, ref) if (d - ref).days >= 0]
    return min(upcoming) if upcoming else None


_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%d/%m/%Y %H:%M",
    "%d/%m/%Y",
    "%m/%d/%Y %I:%M %p",
    "%m/%d/%Y %H:%M",
    "%m/%d/%Y",
    "%m/%d/%y %I:%M %p",
    "%m/%d/%y %H:%M",
    "%m/%d/%y",
    "%d-%m-%Y",
    "%d %b %Y",
    "%d %B %Y",
]


def parse_datetime(value: str) -> Optional[datetime]:
    value = (value or "").strip()
    for fmt in _FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None
