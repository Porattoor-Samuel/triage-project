"""Shared helpers for matching vocabulary lists against text."""
from __future__ import annotations

import re
from functools import lru_cache


@lru_cache(maxsize=None)
def _pattern(term: str) -> re.Pattern:
    if term.endswith("*"):
        body = re.escape(term[:-1]) + r"\w*"
    else:
        body = re.escape(term) + r"(?:s|es)?"
    return re.compile(rf"(?<!\w){body}(?!\w)", re.I)


def find_terms(text: str, terms: list[str]) -> list[str]:
    """Return the matched snippets (as written in the text) for every term that appears."""
    hits = []
    for term in terms:
        m = _pattern(term).search(text)
        if m:
            hits.append(m.group(0))
    return hits
