"""THREAT: is the email potentially risky?  Additive, explainable scoring."""
from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

from . import config
from .models import Email, Evidence
from .rules import find_terms

AMOUNT_RE = re.compile(r"(?:₹|\brs\.?|\binr\b|\busd\b|\$)\s?\d[\d,]*", re.I)
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
NO_WARNING = "No warning signs found"


def sender_domain(sender: str) -> str:
    addr = parseaddr(sender)[1]
    return addr.split("@")[-1].lower() if "@" in addr else ""


def _host(url: str) -> str:
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower()


def _is_trusted(domain: str, trusted: list[str]) -> bool:
    return any(domain == t or domain.endswith("." + t) for t in trusted)


def _is_lookalike(domain: str, trusted: list[str]) -> bool:
    if not domain or _is_trusted(domain, trusted):
        return False
    return any(t.split(".")[0] in domain for t in trusted)


def analyze_threat(email: Email, trusted_domains: list[str] | None = None) -> tuple[str, int, list[Evidence]]:
    trusted = [d.lower() for d in (trusted_domains if trusted_domains is not None else config.TRUSTED_DOMAINS)]
    text = f"{email.subject}\n{email.body}"
    ev: list[Evidence] = []

    # 1. Payment requests ------------------------------------------------------
    amounts = AMOUNT_RE.findall(text)
    pay_terms = find_terms(text, config.PAYMENT_WORDS)
    if amounts and pay_terms:
        ev.append(Evidence("Payment request", f"amount {amounts[0]!r} with payment wording {pay_terms[0]!r}", 3))
    elif pay_terms:
        ev.append(Evidence("Mentions payment", f"payment wording {pay_terms[0]!r}", 1))

    # 2. Pressure / too-good-to-be-true language -------------------------------
    urgent = find_terms(text, config.URGENCY_WORDS)
    if urgent:
        ev.append(Evidence("Urgent wording", f"found {', '.join(repr(u) for u in urgent[:3])}", 2))
    promises = find_terms(text, config.TOO_GOOD_WORDS)
    if promises:
        ev.append(Evidence("Unrealistic promise", f"found {', '.join(repr(p) for p in promises[:3])}", 2))

    # 3. Credential harvesting ---------------------------------------------------
    creds = find_terms(text, config.CREDENTIAL_WORDS)
    if creds:
        ev.append(Evidence("Asks for login / account details", f"found {', '.join(repr(c) for c in creds[:3])}", 3))

    # 4. Links ---------------------------------------------------------------------
    by_rule: dict[tuple[str, int], list[str]] = {}
    for url in email.links:
        host = _host(url)
        if not host:
            continue
        tld = host.rsplit(".", 1)[-1]
        if host in config.URL_SHORTENERS:
            by_rule.setdefault(("Shortened link hides the destination", 2), []).append(url)
        if IP_RE.match(host):
            by_rule.setdefault(("Link points to a raw IP address", 3), []).append(url)
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            by_rule.setdefault(("Link contains '@' (disguised address)", 2), []).append(url)
        if "xn--" in host:
            by_rule.setdefault(("Link uses punycode (look-alike characters)", 2), []).append(url)
        if tld in config.SUSPICIOUS_TLDS:
            by_rule.setdefault((f"Link uses uncommon '.{tld}' domain", 2), []).append(url)
        if host.count("-") >= 3:
            by_rule.setdefault(("Link domain has many hyphens", 1), []).append(url)
        if _is_lookalike(host, trusted):
            by_rule.setdefault(("Link imitates the official domain", 3), []).append(url)
        if url.lower().startswith("http://") and (creds or amounts):
            by_rule.setdefault(("Unencrypted (http) link on a sensitive request", 1), []).append(url)
    for (rule, weight), urls in by_rule.items():
        ev.append(Evidence(rule, urls[0], weight))

    # 5. Sender ---------------------------------------------------------------------
    domain = sender_domain(email.sender)
    if domain:
        if _is_lookalike(domain, trusted):
            ev.append(Evidence("Sender domain imitates the official domain", domain, 3))
        elif domain in config.FREE_MAIL_DOMAINS:
            claims = find_terms(text, config.OFFICIAL_CLAIMS)
            if claims:
                ev.append(Evidence("Official-sounding message from a free mail address", f"{domain} claims {claims[0]!r}", 2))
        elif _is_trusted(domain, trusted):
            ev.append(Evidence("Sender domain matches the trusted list (not proof of identity)", domain, -2))

    score = max(0, sum(e.weight for e in ev))
    if score >= config.THREAT_SUSPICIOUS:
        label = "Suspicious"
    elif score >= config.THREAT_CAUTION:
        label = "Needs caution"
    else:
        label = NO_WARNING
    return label, score, ev
