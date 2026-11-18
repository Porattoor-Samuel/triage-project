"""TRIAGE - explainable, rule-based email trust-worthiness analysis."""
from .analyzer import analyze_all, analyze_email
from .models import Email, Evidence, Result
from .parser import load_csv, load_eml, load_mbox
from .reports import received_period_counts, sender_rankings

__all__ = [
    "analyze_all", "analyze_email", "Email", "Evidence", "Result",
    "load_csv", "load_eml", "load_mbox", "received_period_counts", "sender_rankings",
]
