"""Evaluate TRIAGE labels, misses, false flags, and optional threat scenarios.

Usage:  python evaluate.py [path/to/labelled.csv]
The CSV needs expected_threat; expected_priority and expected_topic are optional.
An optional scenario column reports threat accuracy by scenario type.
"""
from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path

from triage import analyze_all, load_csv

path = Path(sys.argv[1] if len(sys.argv) > 1 else "data/sample_emails.csv")
emails = load_csv(path.read_bytes())
results = analyze_all(emails)
labelled = [r for r in results if r.email.expected]
with path.open("r", encoding="utf-8-sig", newline="") as stream:
    scenarios = {
        row.get("id", "").strip(): row.get("scenario", "").strip()
        for row in csv.DictReader(stream)
    }

print(f"Test emails used: {len(labelled)}\n")

# Threat is compared as flagged (Suspicious / Needs caution) vs not flagged.
correct = Counter()
totals = Counter()
scenario_correct = Counter()
scenario_totals = Counter()
missed, false_flags, wrong_priority, wrong_topic = [], [], [], []
for r in labelled:
    exp = r.email.expected
    expected_threat = exp.get("threat")
    if expected_threat:
        expected_flag = expected_threat == "Suspicious"
        totals["threat"] += 1
        is_correct = expected_flag == r.flagged
        correct["threat"] += is_correct
        if expected_flag and not r.flagged:
            missed.append(r)
        elif not expected_flag and r.flagged:
            false_flags.append(r)
        scenario = scenarios.get(r.email.id, "")
        if scenario:
            scenario_totals[scenario] += 1
            scenario_correct[scenario] += is_correct
    if exp.get("priority"):
        totals["priority"] += 1
        if exp["priority"] == r.priority:
            correct["priority"] += 1
        else:
            wrong_priority.append(r)
    if exp.get("topic"):
        totals["topic"] += 1
        if exp["topic"] == r.topic:
            correct["topic"] += 1
        else:
            wrong_topic.append(r)

for dim in ("threat", "priority", "topic"):
    if totals[dim]:
        print(f"{dim.capitalize():<9} accuracy: {correct[dim]}/{totals[dim]} = {100 * correct[dim] / totals[dim]:.1f}%")
    else:
        print(f"{dim.capitalize():<9} accuracy: not labeled")

if scenario_totals:
    print("\nThreat accuracy by scenario:")
    for scenario in sorted(scenario_totals):
        count = scenario_totals[scenario]
        print(f"  {scenario:<40} {scenario_correct[scenario]}/{count} = {100 * scenario_correct[scenario] / count:.1f}%")

print(f"\nMissed risky emails      : {len(missed)}")
for r in missed:
    print(f"  - {r.email.id}: {r.email.subject}  (score {r.threat_score})")
print(f"Safe emails wrongly flagged: {len(false_flags)}")
for r in false_flags:
    print(f"  - {r.email.id}: {r.email.subject}  ({r.threat}, score {r.threat_score})")
print(f"Wrong priority           : {len(wrong_priority)}")
for r in wrong_priority:
    print(f"  - {r.email.id}: expected {r.email.expected.get('priority')}, got {r.priority} (score {r.priority_score})")
print(f"Wrong topic              : {len(wrong_topic)}")
for r in wrong_topic:
    print(f"  - {r.email.id}: expected {r.email.expected.get('topic')}, got {r.topic}")

conflicts = [r for r in results if r.timetable == "Possible conflict"]
print(f"\nTimetable conflicts spotted in: {', '.join(r.email.id for r in conflicts) or 'none'}")
