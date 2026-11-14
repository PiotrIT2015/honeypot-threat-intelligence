import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


# =====================================================
# CONFIGURATION
# =====================================================

BASE_DIR = Path(__file__).resolve().parent.parent

ANALYSIS_FILE = BASE_DIR / "data/analysis/ioc_analysis.jsonl"
ALERTS_FILE = BASE_DIR / "data/alerts/alerts.jsonl"
SUMMARY_FILE = BASE_DIR / "data/analysis/analysis_summary.json"


st.set_page_config(
    page_title="Honeypot Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)


# =====================================================
# DATA LOADING
# =====================================================

def load_jsonl(file_path):

    records = []

    if not file_path.exists():
        return records

    with file_path.open("r", encoding="utf-8") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

                if isinstance(record, dict):
                    records.append(record)

            except json.JSONDecodeError:
                continue

    return records


def load_json(file_path):

    if not file_path.exists():
        return {}

    try:

        with file_path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        return data if isinstance(data, dict) else {}

    except (json.JSONDecodeError, OSError):
        return {}


# =====================================================
# DATA NORMALIZATION
# =====================================================

def get_risk_score(record):

    score = record.get("risk_score")

    if score is None:
        score = record.get("score", 0)

    try:
        return int(score)
    except (TypeError, ValueError):
        return 0


def get_severity(record):

    severity = record.get("severity", "low")

    return str(severity).lower()


def get_ip(record):

    return (
        record.get("ip")
        or record.get("src_ip")
        or "Unknown"
    )


def normalize_analysis(records):

    normalized = []

    for record in records:

        enrichment = record.get("enrichment", {})
        behavior = record.get("behavior", {})

        if not isinstance(enrichment, dict):
            enrichment = {}

        if not isinstance(behavior, dict):
            behavior = {}

        normalized.append({

            "IP Address": get_ip(record),

            "Risk Score": get_risk_score(record),

            "Severity": get_severity(record),

            "Country": (
                enrichment.get("country")
                or record.get("country")
                or "Unknown"
            ),

            "Malicious": enrichment.get(
                "malicious",
                record.get("malicious", 0)
            ),

            "Suspicious": enrichment.get(
                "suspicious",
                record.get("suspicious", 0)
            ),

            "Failed Logins": behavior.get(
                "failed_logins",
                record.get("failed_logins", 0)
            ),

            "Commands": behavior.get(
                "commands",
                record.get("commands", 0)
            ),

            "File Transfers": behavior.get(
                "file_transfers",
                record.get("file_transfers", 0)
            ),

            "Reasons": ", ".join(
                record.get("reasons", [])
            ) if isinstance(record.get("reasons", []), list)
            else str(record.get("reasons", ""))

        })

    return pd.DataFrame(normalized)


# =====================================================
# LOAD DATA
# =====================================================

analysis_records = load_jsonl(ANALYSIS_FILE)
alert_records = load_jsonl(ALERTS_FILE)
summary = load_json(SUMMARY_FILE)

df = normalize_analysis(analysis_records)
alerts_df = pd.DataFrame(alert_records)


# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.title("🛡️ Security Center")

st.sidebar.markdown(
    """
    **Honeypot Threat Intelligence**

    Security monitoring and IOC analysis.
    """
)

st.sidebar.markdown("---")

st.sidebar.subheader("Filters")

if not df.empty:

    severity_options = sorted(
        df["Severity"].dropna().unique().tolist()
    )

    selected_severities = st.sidebar.multiselect(
        "Threat Severity",
        options=severity_options,
        default=severity_options
    )

    ip_options = sorted(
        df["IP Address"].dropna().unique().tolist()
    )

    selected_ips = st.sidebar.multiselect(
        "IP Address",
        options=ip_options,
        default=ip_options
    )

    filtered_df = df[
        df["Severity"].isin(selected_severities)
        & df["IP Address"].isin(selected_ips)
    ]

else:

    filtered_df = pd.DataFrame()


# =====================================================
# HEADER
# =====================================================

st.title("🛡️ Honeypot Threat Intelligence Dashboard")

st.caption(
    "Cowrie Honeypot | Threat Intelligence | IOC Analysis"
)

st.markdown("---")


# =====================================================
# DATA VALIDATION
# =====================================================

if not ANALYSIS_FILE.exists():

    st.warning(
        "IOC analysis file not found. "
        "Run the IOC Analysis Engine first."
    )

if df.empty:

    st.info(
        "No analysis data available. "
        "The dashboard will display results after data collection."
    )


# =====================================================
# OVERVIEW METRICS
# =====================================================

total_events = summary.get(
    "total_events",
    0
)

analyzed_ips = summary.get(
    "analyzed_ips",
    len(df)
)

total_alerts = summary.get(
    "total_alerts",
    len(alert_records)
)

critical_alerts = summary.get(
    "critical",
    0
)

if isinstance(summary.get("severity_counts"), dict):

    critical_alerts = summary["severity_counts"].get(
        "critical",
        critical_alerts
    )

elif isinstance(summary.get("severity"), dict):

    critical_alerts = summary["severity"].get(
        "critical",
        critical_alerts
    )


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Events",
    total_events
)

col2.metric(
    "Analyzed IPs",
    analyzed_ips
)

col3.metric(
    "Total Alerts",
    total_alerts
)

col4.metric(
    "Critical Alerts",
    critical_alerts
)


st.markdown("---")


# =====================================================
# THREAT SEVERITY
# =====================================================

st.subheader("Threat Severity Distribution")

if not df.empty:

    severity_counts = (
        df["Severity"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = [
        "Severity",
        "Count"
    ]

    fig = px.pie(
        severity_counts,
        names="Severity",
        values="Count",
        hole=0.45,
        title="Distribution of Threat Levels"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

else:

    st.info("Severity statistics are not available.")


st.markdown("---")


# =====================================================
# IOC ANALYSIS
# =====================================================

st.subheader("IOC Analysis")

if not filtered_df.empty:

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )

    fig = px.bar(
        filtered_df.sort_values(
            "Risk Score",
            ascending=False
        ),
        x="IP Address",
        y="Risk Score",
        color="Severity",
        title="Risk Score by IP Address",
        hover_data=[
            "Malicious",
            "Suspicious",
            "Failed Logins"
        ]
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

else:

    st.info("No IOC records match the selected filters.")


st.markdown("---")


# =====================================================
# SECURITY ALERTS
# =====================================================

st.subheader("🚨 Security Alerts")

if not alerts_df.empty:

    preferred_columns = [
        "timestamp",
        "generated_at",
        "ip",
        "src_ip",
        "severity",
        "risk_score",
        "reasons"
    ]

    available_columns = [
        column
        for column in preferred_columns
        if column in alerts_df.columns
    ]

    if available_columns:

        st.dataframe(
            alerts_df[available_columns],
            use_container_width=True,
            hide_index=True
        )

    else:

        st.dataframe(
            alerts_df,
            use_container_width=True,
            hide_index=True
        )

else:

    st.success("No security alerts available.")


st.markdown("---")


# =====================================================
# THREAT INTELLIGENCE
# =====================================================

st.subheader("🌐 Threat Intelligence")

if not filtered_df.empty:

    threat_columns = [
        "IP Address",
        "Country",
        "Malicious",
        "Suspicious"
    ]

    st.dataframe(
        filtered_df[threat_columns],
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("Threat intelligence data is not available.")


# =====================================================
# FOOTER
# =====================================================

st.markdown("---")

st.caption(
    "Honeypot Threat Intelligence Platform | "
    "Python · Streamlit · Cowrie · VirusTotal"
)

st.caption(
    "Educational cybersecurity project. "
    "Threat scores are heuristic indicators, not definitive verdicts."
)