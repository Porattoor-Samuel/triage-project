from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Email:
    id: str
    sender: str
    subject: str
    body: str
    date: Optional[datetime] = None
    links: list[str] = field(default_factory=list)
    expected: dict[str, str] = field(default_factory=dict)  # optional ground-truth labels


@dataclass
class Evidence:
    """One triggered rule plus the text that triggered it."""
    rule: str
    detail: str
    weight: int


@dataclass
class Result:
    email: Email
    threat: str = "No warning signs found"
    threat_score: int = 0
    threat_evidence: list[Evidence] = field(default_factory=list)
    priority: str = "Normal"
    priority_score: int = 0
    priority_evidence: list[Evidence] = field(default_factory=list)
    topic: str = "Other"
    topic_evidence: list[Evidence] = field(default_factory=list)
    timetable: str = "None"  # None | Timetable email | Revised notice | Possible conflict
    timetable_notes: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return self.threat != "No warning signs found"

    def reason(self) -> str:
        """Short, human-readable explanation shown in the results table."""
        parts = []
        risky = sorted((e for e in self.threat_evidence if e.weight > 0), key=lambda e: -e.weight)[:3]
        if risky:
            parts.append("; ".join(e.rule for e in risky))
        elif self.threat == "No warning signs found":
            parts.append("No warning signs found")
        if self.priority_evidence:
            parts.append(self.priority_evidence[0].rule)
        if self.timetable != "None":
            parts.append(self.timetable)
        return " | ".join(p for p in parts if p)

    def to_row(self) -> dict:
        return {
            "ID": self.email.id,
            "Sender": self.email.sender,
            "Subject": self.email.subject,
            "Threat": self.threat,
            "Priority": self.priority,
            "Topic": self.topic,
            "Timetable": self.timetable,
            "Why": self.reason(),
        }
