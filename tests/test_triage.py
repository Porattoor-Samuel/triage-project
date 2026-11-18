import csv
from datetime import date, datetime
from pathlib import Path

from triage import (
    Email,
    analyze_all,
    analyze_email,
    load_csv,
    load_eml,
    load_mbox,
    received_period_counts,
    sender_rankings,
)


def mk(subject, body, sender="x@woxsen.edu.in", when="2026-11-08 09:00", eid="t"):
    return Email(eid, sender, subject, body, datetime.strptime(when, "%Y-%m-%d %H:%M"))


def test_internship_scam_is_suspicious_high_placement():
    r = analyze_email(mk("Guaranteed internship", "Pay ₹999 within 24 hours: https://bit.ly/x", sender="hr@gmail.com"))
    r2 = analyze_all([Email("s", "hr@gmail.com", "Guaranteed internship", "Pay ₹999 within 24 hours: https://bit.ly/x",
                            datetime(2026, 11, 8, 9), ["https://bit.ly/x"])])[0]
    assert r2.threat == "Suspicious"
    assert r2.priority == "High"
    assert r2.topic == "Internship/Placement"
    assert any("Payment" in e.rule for e in r2.threat_evidence)


def test_exam_tomorrow_is_high_academics_no_warning():
    r = analyze_email(mk("Examination tomorrow", "Your exam is tomorrow at 10 AM. Carry your hall ticket."))
    assert (r.threat, r.priority, r.topic) == ("No warning signs found", "High", "Academics")


def test_hostel_next_week_is_normal():
    r = analyze_email(mk("Hostel notice", "Room inspection next week in the hostel."))
    assert (r.priority, r.topic) == ("Normal", "Hostel")


def test_newsletter_is_low():
    assert analyze_email(mk("Weekly newsletter", "Your weekly digest. Unsubscribe any time.")).priority == "Low"


def test_lookalike_sender_domain_flagged():
    r = analyze_email(mk("Hi", "Please log in to verify your account.", sender="it@woxsen-edu.in"))
    assert r.flagged


def test_timetable_conflict_detected():
    a = mk("Exam timetable", "CS301 exam schedule - 12 Dec 2026", eid="a")
    b = mk("Revised exam timetable", "CS301 exam schedule - 15 Dec 2026", eid="b")
    ra, rb = analyze_all([a, b])
    assert ra.timetable == rb.timetable == "Possible conflict"


def test_same_dates_no_conflict():
    a = mk("Exam timetable", "CS301 exam schedule - 12 Dec 2026", eid="a")
    b = mk("Exam timetable copy", "CS301 exam schedule - 12 Dec 2026", eid="b")
    assert all(r.timetable != "Possible conflict" for r in analyze_all([a, b]))


def test_eml_html_links_extracted():
    raw = open("data/eml/phishing_login.eml", "rb").read()
    em = load_eml(raw, "phishing_login.eml")
    assert "http://192.168.4.25/login" in em.links
    r = analyze_all([em])[0]
    assert r.threat == "Suspicious"


def test_csv_loader_reads_expected_labels():
    emails = load_csv(open("data/sample_emails.csv", "rb").read())
    assert len(emails) == 18 and emails[0].expected["threat"] == "Suspicious"


def test_builtin_test_sets_load_labeled_cases():
    data_dir = Path(__file__).parents[1] / "data"
    test_sets = [
        "sample_emails.csv",
        "security_scenarios.csv",
        "advanced_threat_scenarios.csv",
        "threat_type_accuracy.csv",
        "student_inbox.csv",
        "timetable_edge_cases.csv",
    ]

    for filename in test_sets:
        emails = load_csv((data_dir / filename).read_bytes(), prefix=filename)
        assert len(emails) >= 15
        assert all(email.expected for email in emails)


def test_threat_type_accuracy_cases_have_balanced_labels():
    path = Path(__file__).parents[1] / "data" / "threat_type_accuracy.csv"
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))

    grouped = {}
    for row in rows:
        grouped.setdefault(row["scenario"].strip(), []).append(row["expected_threat"])

    assert len(rows) == 70
    assert len(grouped) == 7
    assert all(
        labels.count("Suspicious") == 5 and labels.count("No warning signs found") == 5
        for labels in grouped.values()
    )


def test_outlook_csv_export_headers_and_received_date():
    data = (
        "From: (Name),From: (Address),Subject,Received,Body\n"
        '"Campus Office",office@example.edu,Exam notice,11/09/2026 10:30 AM,Exam tomorrow\n'
    )
    email = load_csv(data)[0]
    assert email.sender == "office@example.edu"
    assert email.subject == "Exam notice"
    assert email.date == datetime(2026, 11, 9, 10, 30)


def test_mbox_loader_reads_all_messages():
    data = b"""From sender1@example.com Mon Nov 09 10:00:00 2026
From: Sender One <sender1@example.com>
To: student@example.edu
Subject: First message
Date: Mon, 09 Nov 2026 10:00:00 +0000

First body
From sender2@example.com Mon Nov 09 11:00:00 2026
From: Sender Two <sender2@example.com>
To: student@example.edu
Subject: Second message
Date: Mon, 09 Nov 2026 11:00:00 +0000

Second body
"""
    emails = load_mbox(data, "takeout.mbox")
    assert len(emails) == 2
    assert [email.subject for email in emails] == ["First message", "Second message"]
    assert [email.id for email in emails] == ["takeout-1", "takeout-2"]


def test_mailbox_report_periods_and_sender_rankings():
    emails = [
        Email("1", "Alice <ALICE@example.com>", "one", "", datetime(2026, 11, 9, 9)),
        Email("2", "alice@example.com", "two", "", datetime(2026, 11, 8, 9)),
        Email("3", "Bob <bob@example.com>", "three", "", datetime(2026, 11, 2, 9)),
        Email("4", "future@example.com", "future", "", datetime(2026, 11, 10, 9)),
        Email("5", "undated@example.com", "unknown", ""),
    ]
    assert received_period_counts(emails, date(2026, 11, 9)) == {
        "Today": 1,
        "This week": 1,
        "This month": 3,
        "This year": 3,
    }
    ranking = sender_rankings(emails)
    assert ranking[0] == {"Rank": 1, "Sender": "ALICE@example.com", "Emails": 2}
    assert ranking[1]["Rank"] == ranking[2]["Rank"] == 2
