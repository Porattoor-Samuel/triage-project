# TRIAGE – Explainable Rule-Based Email Trust-Worthiness Analysis

A standalone prototype that examines each email from three independent angles and explains every result:

| Perspective | Question | Output |
|---|---|---|
| **Threat** | Is it potentially risky? | Suspicious / Needs caution / No warning signs found |
| **Priority** | How soon should it be reviewed? | High / Normal / Low |
| **Topic** | What is it about? | Academics, Internship/Placement, Hostel, Clubs/Events, Administrative, Other |

It also compares examination-timetable emails and flags **possible date conflicts** or **revised notices**.
Email threat, priority, and topic labels use predefined rules. A separate local logistic-regression
model evaluates URL structure in links found in each email; it does not replace the email threat label.
TRIAGE does not connect to live email accounts.

The Streamlit dashboard uses navy `#14213D`, slate `#475569`, light surface
`#F4F6FA`, and blue accent `#2563EB`, with light and dark appearances. The
extension popup and in-mail overlay use a dark charcoal surface with a blue
accent and red, amber, and green status colors.

> "No warning signs found" does **not** mean the sender is verified or the email is safe.

## Run it

```bash
pip install -r requirements.txt
streamlit run app.py          # dashboard
python evaluate.py            # accuracy on labelled test emails
pytest                        # unit tests
```

## Project layout

```
app.py                  Streamlit dashboard (search, filters, per-email explanation)
evaluate.py             Evaluation: accuracy, missed risky emails, false flags
triage/
  config.py             ALL keyword lists, thresholds and trusted domains  <- tune here
  parser.py             EMAIL READER: .eml and .csv -> Email (sender, subject, body, links, date)
  reports.py            Uploaded-mailbox date counts and sender rankings
  dates.py              Date extraction (12 Dec 2026, 12/12/2026, tomorrow, within 24 hours, ...)
  threat.py             Email threat rules (payment, urgency, credentials, links, sender)
  url_model.py          URL feature extraction and locally trained phishing model
  priority.py           Priority rules (keywords + how near the deadline is)
  topic.py              Topic keyword scoring
  timetable.py          Timetable detection and cross-email conflict check
  analyzer.py           Runs everything and builds the Result
data/sample_emails.csv  18 synthetic labelled emails
data/security_scenarios.csv  15 synthetic security and phishing cases
data/advanced_threat_scenarios.csv  15 synthetic advanced-threat cases and benign controls
data/threat_type_accuracy.csv  70 balanced synthetic cases across seven threat types
data/student_inbox.csv  15 synthetic messages across student topics
data/timetable_edge_cases.csv  15 synthetic timetable and edge cases
data/phishing-dataset-variation.csv  Labeled URL-feature training data for the URL model
data/eml/               Seven sample .eml files for scam, routine, and timetable scenarios
tests/                  pytest suite
```

The dashboard sidebar lets you switch between the built-in test sets. The
advanced threat set covers business-email compromise, attachment warning
indicators, sender/header spoofing, QR-code credential theft, and malicious
links. It uses reserved example domains and inert attachment names, not real
malware or live phishing destinations. Attachment and authentication-header
columns document intended test inputs; the current parser does not inspect
those fields, so those cases are expected to reveal detection gaps. Evaluate
that set with `python evaluate.py data/advanced_threat_scenarios.csv`.

For per-type threat accuracy, select **Threat-type accuracy tests (70)** in the
dashboard or run `python evaluate.py data/threat_type_accuracy.csv`. It has ten
cases per category (five expected threats and five benign controls) and reports
threat accuracy by category. It covers business-email compromise, attachment
indicators, sender/authentication spoofing, executive impersonation, credential
and QR phishing, suspicious links, and pressure/false promises. The extra
attachment and header columns are test notes only; the current parser does not
inspect them. URL examples are analyzed as text and the evaluator does not open
or resolve them. These are small, synthetic demonstration results, not
real-world accuracy estimates; a 100% score means only that all ten cases in
that category were classified correctly.

Uploaded
`.eml`, `.csv`, and `.mbox` files are analyzed alongside the selected set;
choose **Uploaded files only** to omit built-in examples. Emails containing links
also receive a separate URL model signal in the mail table and selected-email
details. The first run trains the model from the included 88,647-row feature
dataset; the trained model is cached for the running app.

The URL dataset contains URL/domain feature measurements and a `phishing` label,
not email messages or raw URLs. TRIAGE trains on structural features it can
derive from links locally (such as URL length, punctuation, and domain shape).
It excludes network-dependent fields such as domain age, DNS/ASN, response time,
and search-engine indexing. Its displayed holdout metrics come from a random,
stratified split of that same dataset and are not a guarantee of real-world
accuracy. URL findings remain a separate signal; a low URL score does not verify
the sender or destination.

The Mailbox report uses uploaded messages only, so built-in synthetic examples
do not affect its counts or sender rankings.

For mailbox reports, upload a Gmail Takeout `.mbox` file or a mailbox `.csv`
export containing sender, subject, body, and a received date. The report shows
counts for today, the Monday-based current week, current month, and current
year; ranks sender email addresses by message count; and lists each message's
threat level, score, evidence, priority, topic, body, and links. Period counts
use the reference date in the sidebar. Messages without a recognized received
date are included in message and sender totals but not in date-period counts.
TRIAGE does not connect to or scan a live mailbox, and only the messages present
in the uploaded export are included.

To try the sample `.eml` messages, choose **Uploaded files only** in the
dashboard and upload one or more files from `data/eml/`. The two timetable
examples should be uploaded together to see the date-conflict alert.

## Chrome and Edge extension

The `extension/` folder contains a local-only Manifest V3 extension for Gmail
and Outlook on the web (`outlook.live.com`, `outlook.office.com`,
`outlook.office365.com`, and `outlook.cloud.microsoft`). It automatically
checks for an open message and opens the TRIAGE overlay when a message is
detected, then saves recent results in the browser's extension storage. Message
content is analyzed in the browser and is not sent to the Streamlit app or a
remote service.
If a message is marked **Suspicious** or **Needs caution**, its page overlay lets
you mark it as safe or undo that mark later. This is a personal annotation:
TRIAGE keeps the original automated score and evidence unchanged, and the
extension dashboard records the annotation alongside the original result.

To load the development version:

1. Open `chrome://extensions` in Chrome or `edge://extensions` in Edge.
2. Turn on **Developer mode**.
3. Choose **Load unpacked** and select this project's `extension` folder.
4. Refresh the Gmail (`mail.google.com`) or Outlook on the web tab after
   installing/reloading the extension. Open a message; TRIAGE should analyze it
   and open its overlay automatically. The overlay closes when no open message
   is detected. Click the toolbar icon to view recent results stored by the
   extension.
5. To view mailbox reports, start the Streamlit app separately from the project
   folder with `streamlit run app.py`, then upload a mailbox export in the app.
   The extension popup does not link to or open the Streamlit dashboard.

If the extension says it cannot contact TRIAGE in the current tab, refresh the
mail tab and open an email again. Browser extensions cannot inject
their content scripts into a tab that was already open before installation or
an extension reload until that tab is refreshed.

After updating the extension files, reload TRIAGE from the browser's extensions
page, then refresh Outlook. Outlook's web interface changes over time, so email
body detection can still vary by account and layout.

The extension uses heuristic rules and can miss scams or flag legitimate
messages. "No warning signs found" does not verify the sender or mean an email
is safe. Gmail and Outlook may change their page markup, which can affect
message detection. This prototype does not connect to native desktop mail
applications or Outlook desktop.

## Input formats

* **EML** – standard `.eml` files (plain text or HTML bodies; links in `<a href>` are extracted).
* **MBOX** – Gmail Takeout mailbox archives.
* **CSV** – columns `sender, subject, body` plus optional `date, id`; common
  Outlook export headers such as `From: (Address)` and `Received` are also
  supported. For evaluation add
  `expected_threat, expected_priority, expected_topic`.

## How scoring works

Each rule adds or subtracts points and records the evidence, so every label can be traced.

* **Threat:** score ≥ 5 → *Suspicious*, ≥ 2 → *Needs caution*, otherwise *No warning signs found*.
  Examples: payment request +3, urgent wording +2, login/OTP request +3, raw-IP link +3, URL shortener +2,
  look-alike domain +3, official-sounding mail from a free address +2, trusted domain −2.
* **Priority:** score ≥ 3 → *High*, ≤ −1 → *Low*. Important keywords +2, a date within 2 days +3,
  suspicious threat +3, newsletter-type wording −2.
* **Topic:** keyword hits (subject hits count double); at least 2 points needed, else *Other*.

**Before use, set `TRUSTED_DOMAINS` in `triage/config.py` to your institution's domain** (the default
`woxsen.edu.in` is an assumption).

## Known limitations

* Rules can miss new or cleverly worded scams, and can wrongly flag legitimate emails (for example a real fee notice).
* Sender identity is not verified – a trusted-looking domain can be spoofed.
* TRIAGE cannot say which of two conflicting timetables is official.
* The sample set is synthetic and the rules were tuned on it, so its accuracy figures are optimistic;
  evaluate on fresh emails for honest numbers.
