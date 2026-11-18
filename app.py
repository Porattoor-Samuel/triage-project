from __future__ import annotations

from datetime import date
from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st

from triage import (
    analyze_all,
    config,
    load_csv,
    load_eml,
    load_mbox,
    received_period_counts,
    sender_rankings,
)
from triage.url_model import URLPhishingModel, URLPrediction, train_url_model

st.set_page_config(page_title="TRIAGE", page_icon=":material/inbox:", layout="wide")

SAMPLE = Path(__file__).parent / "data" / "sample_emails.csv"
URL_DATASET = Path(__file__).parent / "data" / "phishing-dataset-variation.csv"
TEST_SETS = {
    "Original examples (18)": SAMPLE,
    "Security and phishing (15)": SAMPLE.parent / "security_scenarios.csv",
    "Advanced threat scenarios (15)": SAMPLE.parent / "advanced_threat_scenarios.csv",
    "Threat-type accuracy tests (70)": SAMPLE.parent / "threat_type_accuracy.csv",
    "Student inbox topics (15)": SAMPLE.parent / "student_inbox.csv",
    "Timetable and edge cases (15)": SAMPLE.parent / "timetable_edge_cases.csv",
    "Uploaded files only": None,
}


@st.cache_resource(show_spinner=False)
def get_url_model(dataset_path: str) -> URLPhishingModel:
    return train_url_model(dataset_path)


def summarize_url_checks(predictions: list[URLPrediction]) -> str:
    if not predictions:
        return "No links"
    scored = [prediction for prediction in predictions if prediction.score is not None]
    if not scored:
        return "Could not assess URL"
    highest = max(scored, key=lambda prediction: prediction.score or 0)
    return f"{highest.threat} ({highest.score:.0%}); {len(scored)}/{len(predictions)} links assessed"


def format_url_findings(predictions: list[URLPrediction]) -> str:
    return "; ".join(
        f"{prediction.url} — {prediction.threat}"
        + (f" ({prediction.score:.0%})" if prediction.score is not None else "")
        for prediction in predictions
    )
dark_mode = st.context.theme.type == "dark"
status_colors = {
    "threat": {
        "suspicious": "#FDA29B" if dark_mode else "#B42318",
        "caution": "#FEC84B" if dark_mode else "#B54708",
        "safe": "#6CE9A6" if dark_mode else "#027A48",
    },
    "priority": {
        "high": "#FDA29B" if dark_mode else "#B42318",
        "normal": "#FEC84B" if dark_mode else "#B54708",
        "low": "#6CE9A6" if dark_mode else "#027A48",
    },
}
table_colors = {
    "background": "#14213D" if dark_mode else "#F4F6FA",
    "text": "#F4F6FA" if dark_mode else "#14213D",
    "header": "#475569" if dark_mode else "#14213D",
    "border": "#475569",
}

st.markdown(
    f"""
    <style>
    .threat-suspicious, .priority-high {{ color: {status_colors["threat"]["suspicious"]}; font-weight: 700; }}
    .threat-caution, .priority-normal {{ color: {status_colors["threat"]["caution"]}; font-weight: 700; }}
    .threat-safe, .priority-low {{ color: {status_colors["threat"]["safe"]}; font-weight: 700; }}
    </style>
    """,
    unsafe_allow_html=True,
)


def color_label(label, kind):
    if kind == "Threat":
        if label == "Suspicious":
            cls = "threat-suspicious"
        elif label == "Needs caution":
            cls = "threat-caution"
        else:
            cls = "threat-safe"
    else:
        if label == "High":
            cls = "priority-high"
        elif label == "Normal":
            cls = "priority-normal"
        else:
            cls = "priority-low"
    return f'<span class="{cls}">{escape(label)}</span>'


def status_color(label, kind):
    if kind == "Threat":
        key = {
            "Suspicious": "suspicious",
            "Needs caution": "caution",
            "No warning signs found": "safe",
        }[label]
    else:
        key = {"High": "high", "Normal": "normal", "Low": "low"}[label]
    return status_colors[kind.lower()][key]


def status_markdown(label, kind):
    return f'<span style="color:{status_color(label, kind)};font-weight:700">{escape(label)}</span>'


st.title("TRIAGE")
st.caption("Explainable, rule-based email trust-worthiness analysis for secure inbox management")

# ------------------------------------------------------------------ EMAIL INPUT -------------------------------------------------------------- #
with st.sidebar:
    st.header("Email input")
    test_set = st.selectbox("Built-in test set", list(TEST_SETS))
    uploads = st.file_uploader(
        "Upload mailbox exports (.mbox, .csv) or .eml files",
        type=["mbox", "csv", "eml"],
        accept_multiple_files=True,
    )
    st.caption("Uploaded files are analyzed together with the selected built-in set.")
    today = st.date_input("Today's date (for deadlines)", value=date.today())
    trusted_raw = st.text_input("Trusted sender domains (comma-separated)", value=", ".join(config.TRUSTED_DOMAINS))
    trusted = [d.strip().lower() for d in trusted_raw.split(",") if d.strip()]
    st.info("TRIAGE analyzes uploaded files only; it does not connect to a live mailbox.")


@st.cache_data(show_spinner=False)
def read_uploaded_inputs(files: tuple[tuple[str, bytes], ...]):
    emails = []
    for name, data in files:
        suffix = Path(name).suffix.lower()
        if suffix == ".csv":
            emails += load_csv(data, prefix=Path(name).stem)
        elif suffix == ".mbox":
            emails += load_mbox(data, name)
        else:
            emails.append(load_eml(data, name))
    return emails


@st.cache_data(show_spinner=False)
def read_inputs(files: tuple[tuple[str, bytes], ...], dataset_name: str, dataset_data: bytes | None):
    emails = []
    if dataset_data is not None:
        emails += load_csv(dataset_data, prefix=Path(dataset_name).stem)
    emails += read_uploaded_inputs(files)
    return emails


selected_dataset = TEST_SETS[test_set]
dataset_name = selected_dataset.name if selected_dataset else ""
dataset_data = selected_dataset.read_bytes() if selected_dataset else None
uploaded_files = tuple((f.name, f.getvalue()) for f in uploads or [])
uploaded_emails = read_uploaded_inputs(uploaded_files)
emails = read_inputs(uploaded_files, dataset_name, dataset_data)
if not emails:
    st.warning("Choose a built-in test set or upload .eml/.csv files in the sidebar to begin.")
    st.stop()

results = analyze_all(emails, today=today, trusted_domains=trusted)
url_model = None
email_url_checks: list[list[URLPrediction]] = [[] for _ in results]
if any(result.email.links for result in results):
    with st.spinner("Training the URL phishing model from the included dataset..."):
        url_model = get_url_model(str(URL_DATASET))
    email_url_checks = [url_model.assess(result.email.links) for result in results]

df = pd.DataFrame([r.to_row() for r in results])
df["URL model signal"] = [summarize_url_checks(checks) for checks in email_url_checks]

if url_model is not None:
    st.caption(
        f"URL model: {url_model.dataset_rows:,} labeled URL-feature rows; "
        f"held-out accuracy {url_model.accuracy:.1%}, precision {url_model.precision:.1%}, "
        f"recall {url_model.recall:.1%}, F1 {url_model.f1:.1%}. "
        "URL signals are a separate heuristic model result and do not replace the email threat label."
    )

# --------------------------------------------------------------------- DASHBOARD ----------------------------------------------------- #
c1, c2, c3, c4 = st.columns(4)
c1.metric("Emails analysed", len(df))
c2.metric("Suspicious / caution", int((df["Threat"] != "No warning signs found").sum()))
c3.metric("High priority", int((df["Priority"] == "High").sum()))
c4.metric("Timetable alerts", int(df["Timetable"].isin(["Possible conflict", "Revised notice"]).sum()))

st.subheader("Mailbox report")
st.caption(
    "This report covers messages in the uploaded export only. "
    "The week is Monday–Sunday; period counts use the reference date selected in the sidebar."
)
if not uploaded_emails:
    st.info("Upload a mailbox .mbox or .csv export to see received-message counts and sender rankings.")
else:
    report_results = analyze_all(uploaded_emails, today=today, trusted_domains=trusted)
    report_url_checks = [url_model.assess(result.email.links) for result in report_results] if url_model else [
        [] for _ in report_results
    ]
    report_counts = received_period_counts(uploaded_emails, today)
    count_columns = st.columns(4)
    for column, period in zip(count_columns, ("Today", "This week", "This month", "This year")):
        column.metric(period, report_counts[period])

    undated_count = sum(email.date is None for email in uploaded_emails)
    if undated_count:
        st.caption(f"{undated_count} uploaded message(s) have no recognized received date and are excluded from period counts.")

    st.markdown("**Senders ranked by number of messages**")
    ranking_df = pd.DataFrame(sender_rankings(uploaded_emails))
    st.dataframe(ranking_df, hide_index=True, alt="Senders ranked by uploaded message count")
    st.markdown("**Threat report for uploaded messages**")
    report_df = pd.DataFrame(
        [
            {
                "Mail ID": result.email.id,
                "Received": result.email.date.isoformat(sep=" ") if result.email.date else "",
                "Sender": result.email.sender,
                "Subject": result.email.subject,
                "Threat level": result.threat,
                "Threat score": result.threat_score,
                "Threat evidence": "; ".join(
                    f"{item.rule} ({item.weight:+d})" for item in result.threat_evidence
                ),
                "URL model signal": summarize_url_checks(url_checks),
                "URL findings": format_url_findings(url_checks),
                "Priority": result.priority,
                "Topic": result.topic,
                "Body": result.email.body,
                "Links": ", ".join(result.email.links),
            }
            for result, url_checks in zip(report_results, report_url_checks, strict=True)
        ]
    )
    report_styler = report_df.style.apply(
        lambda values: [f"color: {status_color(value, 'Threat')}; font-weight: 700;" for value in values],
        subset=["Threat level"],
    ).apply(
        lambda values: [f"color: {status_color(value, 'Priority')}; font-weight: 700;" for value in values],
        subset=["Priority"],
    )
    st.dataframe(
        report_styler,
        hide_index=True,
        alt="Uploaded email report with message and URL threat assessments",
    )
    st.download_button(
        "Download mailbox report (CSV)",
        report_df.to_csv(index=False).encode("utf-8"),
        "triage_mailbox_report.csv",
        "text/csv",
    )

f1, f2, f3, f4 = st.columns([1, 1, 1, 2])
threat_f = f1.multiselect("Threat", sorted(df["Threat"].unique()))
prio_f = f2.multiselect("Priority", ["High", "Normal", "Low"])
topic_f = f3.multiselect("Topic", sorted(df["Topic"].unique()))
query = f4.text_input("Search sender / subject / body")

mask = pd.Series(True, index=df.index)
if threat_f:
    mask &= df["Threat"].isin(threat_f)
if prio_f:
    mask &= df["Priority"].isin(prio_f)
if topic_f:
    mask &= df["Topic"].isin(topic_f)
if query:
    q = query.lower()
    mask &= pd.Series(
        [q in f"{r.email.sender} {r.email.subject} {r.email.body}".lower() for r in results], index=df.index
    )

view = df[mask].copy()
filtered_rows = [
    (result, checks)
    for result, checks, keep in zip(results, email_url_checks, mask, strict=True)
    if keep
]
html_rows = [
    f"<table style='width:100%; border-collapse:collapse; background:{table_colors['background']}; color:{table_colors['text']};'>",
    f"<thead><tr style='background:{table_colors['header']}; color:#F4F6FA;'>"
    "<th style='text-align:left; padding:10px;'>ID</th>"
    "<th style='text-align:left; padding:10px;'>Sender</th>"
    "<th style='text-align:left; padding:10px;'>Subject</th>"
    "<th style='text-align:left; padding:10px;'>Threat</th>"
    "<th style='text-align:left; padding:10px;'>Priority</th>"
    "<th style='text-align:left; padding:10px;'>URL model signal</th>"
    "<th style='text-align:left; padding:10px;'>Topic</th>"
    "<th style='text-align:left; padding:10px;'>Timetable</th>"
    "</tr></thead><tbody>",
]
for r, url_checks in filtered_rows:
    html_rows.append(
        "<tr>"
        f"<td style='padding:10px; border-top:1px solid {table_colors['border']};'>{escape(r.email.id)}</td>"
        f"<td style='padding:10px; border-top:1px solid {table_colors['border']};'>{escape(r.email.sender)}</td>"
        f"<td style='padding:10px; border-top:1px solid {table_colors['border']};'>{escape(r.email.subject)}</td>"
        f"<td style='padding:10px; border-top:1px solid {table_colors['border']};'>{color_label(r.threat, 'Threat')}</td>"
        f"<td style='padding:10px; border-top:1px solid {table_colors['border']};'>{color_label(r.priority, 'Priority')}</td>"
        f"<td style='padding:10px; border-top:1px solid {table_colors['border']};'>{escape(summarize_url_checks(url_checks))}</td>"
        f"<td style='padding:10px; border-top:1px solid {table_colors['border']};'>{escape(r.topic)}</td>"
        f"<td style='padding:10px; border-top:1px solid {table_colors['border']};'>{escape(r.timetable)}</td>"
        "</tr>"
    )
html_rows.append("</tbody></table>")
st.markdown("\n".join(html_rows), unsafe_allow_html=True)
st.download_button("Download results (CSV)", df.to_csv(index=False).encode("utf-8"), "triage_results.csv", "text/csv")

# -------------------------------------------------------------- STUDENT ACTION ------------------------------------------------ #
st.subheader("Why was it labelled this way?")
filtered = [(index, result) for index, result, keep in zip(range(len(results)), results, mask, strict=True) if keep]
if not filtered:
    st.info("No emails match the current filters.")
    st.stop()

choice_index, choice = st.selectbox(
    "Pick an email",
    filtered,
    format_func=lambda item: f"{item[1].email.id} - {item[1].email.subject}",
)
em = choice.email
st.markdown(f"**From:** {em.sender}  \n**Date:** {em.date or 'unknown'}  \n**Subject:** {em.subject}")
with st.expander("Show email body and links"):
    st.text(em.body)
    if em.links:
        st.markdown("**Links found:**")
        st.text("\n".join(em.links))

choice_url_checks = email_url_checks[choice_index]
if choice_url_checks:
    st.subheader("URL model checks")
    st.caption(
        "These assessments use URL structure only. They are separate from the email threat label "
        "and do not verify the destination or sender."
    )
    url_rows = [
        f"<table style='width:100%; border-collapse:collapse; background:{table_colors['background']}; color:{table_colors['text']};'>",
        f"<thead><tr style='background:{table_colors['header']}; color:#F4F6FA;'>"
        "<th style='text-align:left; padding:10px;'>Link</th>"
        "<th style='text-align:left; padding:10px;'>URL threat level</th>"
        "<th style='text-align:left; padding:10px;'>Model score</th>"
        "<th style='text-align:left; padding:10px;'>Feature evidence</th>"
        "</tr></thead><tbody>",
    ]
    for prediction in choice_url_checks:
        score = f"{prediction.score:.0%}" if prediction.score is not None else "Unavailable"
        evidence = "; ".join(prediction.evidence) or "No prominent URL-structure signals"
        url_rows.append(
            "<tr>"
            f"<td style='padding:10px; border-top:1px solid {table_colors['border']};'>{escape(prediction.url)}</td>"
            f"<td style='padding:10px; border-top:1px solid {table_colors['border']};'>{escape(prediction.threat)}</td>"
            f"<td style='padding:10px; border-top:1px solid {table_colors['border']};'>{score}</td>"
            f"<td style='padding:10px; border-top:1px solid {table_colors['border']};'>{escape(evidence)}</td>"
            "</tr>"
        )
    url_rows.append("</tbody></table>")
    st.markdown("\n".join(url_rows), unsafe_allow_html=True)

col_t, col_p, col_o = st.columns(3)
with col_t:
    st.markdown(
        f"### Threat\n{status_markdown(choice.threat, 'Threat')} (score {choice.threat_score})",
        unsafe_allow_html=True,
    )
    for e in sorted(choice.threat_evidence, key=lambda e: -e.weight):
        st.markdown(
            f"- **{escape(e.rule)}** `{e.weight:+d}`  \n  <small>{escape(e.detail)}</small>",
            unsafe_allow_html=True,
        )
    if not choice.threat_evidence:
        st.caption("No rules triggered.")
with col_p:
    st.markdown(
        f"### Priority\n{status_markdown(choice.priority, 'Priority')} (score {choice.priority_score})",
        unsafe_allow_html=True,
    )
    for e in choice.priority_evidence:
        st.markdown(f"- {e.rule} `{e.weight:+d}`")
    if not choice.priority_evidence:
        st.caption("No priority rules triggered.")
with col_o:
    st.markdown(f"### Topic\n**{choice.topic}**")
    for e in choice.topic_evidence[:6]:
        st.markdown(f"- {e.rule}")
    if not choice.topic_evidence:
        st.caption("No topic keywords matched strongly enough.")

if choice.timetable != "None":
    st.info(f"**Timetable:** {choice.timetable}")
    for note in choice.timetable_notes:
        st.write(f"- {note}")

# ------------------------------------------------------------ timetable overview ------------------------------------------------ #
conflicts = [r for r in results if r.timetable == "Possible conflict"]
if conflicts:
    st.subheader("Examination timetable alerts")
    for r in conflicts:
        for note in dict.fromkeys(r.timetable_notes):
            st.error(f"{r.email.id}: {note}")