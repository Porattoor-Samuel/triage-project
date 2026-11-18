"""EMAIL READER: turns .eml files and .csv rows into Email objects."""
from __future__ import annotations

import csv
import io
import mailbox
import re
import tempfile
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Union

from .dates import parse_datetime
from .models import Email

URL_RE = re.compile(r"""(?:https?://|\bwww\.)[^\s<>"')\]]+""", re.I)
EXPECTED_COLUMNS = {"expected_threat": "threat", "expected_priority": "priority", "expected_topic": "topic"}
ALIASES = {
    "from": "sender",
    "from: (address)": "sender_address",
    "from (address)": "sender_address",
    "from: (name)": "sender_name",
    "from (name)": "sender_name",
    "message": "body",
    "message body": "body",
    "body text": "body",
    "content": "body",
    "text": "body",
    "title": "subject",
    "subject line": "subject",
    "timestamp": "date",
    "received": "date",
    "received time": "date",
    "date received": "date",
    "message id": "id",
}


class _HTMLToText(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.links: list[str] = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip = True
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v and v.lower().startswith(("http", "www")):
                    self.links.append(v)
        if tag in ("br", "p", "div", "tr", "li"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def extract_links(text: str, extra: list[str] | None = None) -> list[str]:
    seen: dict[str, None] = {}
    for url in list(URL_RE.findall(text or "")) + list(extra or []):
        seen[url.rstrip(".,;:!?")] = None
    return list(seen)


def load_eml(data: bytes, name: str = "email.eml") -> Email:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    part = msg.get_body(preferencelist=("plain", "html"))
    body, html_links = "", []
    if part is not None:
        content = part.get_content()
        if part.get_content_subtype() == "html":
            stripper = _HTMLToText()
            stripper.feed(content)
            body, html_links = "".join(stripper.parts), stripper.links
        else:
            body = content
    when = None
    if msg["date"]:
        try:
            when = parsedate_to_datetime(str(msg["date"])).replace(tzinfo=None)
        except (TypeError, ValueError):
            when = None
    return Email(
        id=name,
        sender=str(msg["from"] or ""),
        subject=str(msg["subject"] or ""),
        body=body.strip(),
        date=when,
        links=extract_links(body, html_links),
    )


def load_mbox(data: bytes, name: str = "mailbox.mbox") -> list[Email]:
    """Load every message from a Gmail Takeout-style MBOX archive."""
    with tempfile.TemporaryDirectory(prefix="triage-mbox-") as temp_dir:
        path = Path(temp_dir) / Path(name).name
        path.write_bytes(data)
        archive = mailbox.mbox(path, create=False)
        try:
            return [
                load_eml(message.as_bytes(policy=policy.default), f"{Path(name).stem}-{index}")
                for index, message in enumerate(archive, start=1)
            ]
        finally:
            archive.close()


def load_csv(data: Union[bytes, str], prefix: str = "row") -> list[Email]:
    """Load a labeled TRIAGE CSV or common mailbox-export CSV."""
    text = data.decode("utf-8-sig") if isinstance(data, bytes) else data
    emails: list[Email] = []
    for i, raw in enumerate(csv.DictReader(io.StringIO(text)), start=1):
        row = {}
        for key, value in raw.items():
            k = (key or "").strip().lower()
            row[ALIASES.get(k, k)] = (value or "").strip()
        row["sender"] = row.get("sender_address") or row.get("sender") or row.get("sender_name", "")
        expected = {label: row[col] for col, label in EXPECTED_COLUMNS.items() if row.get(col)}
        emails.append(
            Email(
                id=row.get("id") or f"{prefix}-{i}",
                sender=row.get("sender", ""),
                subject=row.get("subject", ""),
                body=row.get("body", ""),
                date=parse_datetime(row.get("date", "")),
                links=extract_links(row.get("body", "")),
                expected=expected,
            )
        )
    return emails
