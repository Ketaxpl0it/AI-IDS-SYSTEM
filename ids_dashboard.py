import json
import time
from collections import Counter, defaultdict
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
import pandas as pd
import streamlit as st

ALERT_FILE = "live_alerts.json"

st.set_page_config(page_title="AI IDS Dashboard", layout="wide")

st.title("🛡️ AI-Powered Intrusion Detection System Dashboard")

# 🔄 Auto refresh every 2 seconds
st_autorefresh(interval=2000, key="ids_refresh")

# -------------------------
# LOAD ALERTS
# -------------------------

def load_alerts():
    try:
        with open(ALERT_FILE) as f:
            return json.load(f)
    except:
        return []


alerts = load_alerts()

if not alerts:
    st.info("Waiting for alerts...")
    st.stop()

df = pd.DataFrame(alerts)
# Backward compatibility if old alerts exist
if "DateTime" not in df.columns and "Time" in df.columns:
    df["DateTime"] = df["Time"]

# -------------------------
# METRICS
# -------------------------

c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Alerts", len(df))
c2.metric("High Severity", (df["Severity"] == "High").sum())
c3.metric("Medium Severity", (df["Severity"] == "Medium").sum())
c4.metric("Unique Attackers", df["Source"].nunique())

# -------------------------
# ALERT TABLE
# -------------------------

st.subheader("🚨 Live Alerts")

st.dataframe(
    df.sort_values("DateTime", ascending=False),
    use_container_width=True,
    height=300
)

# -------------------------
# ANALYTICS ROW
# -------------------------

col1, col2 = st.columns(2)

# ---- Attack Types ----
with col1:
    st.subheader("📊 Attacks by Type")
    type_counts = df["Attack_Type"].value_counts()
    st.bar_chart(type_counts)

# ---- Severity ----
with col2:
    st.subheader("⚠ Severity Distribution")
    sev_counts = df["Severity"].value_counts()
    st.bar_chart(sev_counts)

# -------------------------
# TOP ATTACKERS
# -------------------------

st.subheader("🌍 Top Attacking IPs")

top_ips = df["Source"].value_counts().head(10)
st.bar_chart(top_ips)

# -------------------------
# ALERT TIMELINE
# -------------------------

st.subheader("📈 Alerts Over Time")

df["ParsedTime"] = pd.to_datetime(df["DateTime"], errors="coerce")

timeline = df.set_index("ParsedTime").resample("10S").size()

st.line_chart(timeline)

