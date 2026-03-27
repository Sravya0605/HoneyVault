import streamlit as st
import pandas as pd
from pymongo import MongoClient
from datetime import datetime

# -----------------------------
# Config
# -----------------------------
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "honeyVault"

# Safe Mongo connection
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()  # Force connection check
    db = client[DB_NAME]
    logs_collection = db["logs"]
    db_connected = True
except Exception as e:
    st.error(f"MongoDB connection failed: {e}")
    db_connected = False

st.set_page_config(
    page_title="HoneyVault Dashboard",
    layout="wide"
)

st.title("HoneyVault Security Dashboard")
st.markdown("### Deception-Driven Encryption Monitoring System")

# -----------------------------
# Load Data
# -----------------------------
def load_logs():
    if not db_connected:
        return pd.DataFrame()

    logs = list(logs_collection.find().sort("timestamp", -1))

    if not logs:
        return pd.DataFrame()

    for log in logs:
        log["_id"] = str(log.get("_id", ""))
        log["is_fake"] = bool(log.get("is_fake", False))

    df = pd.DataFrame(logs)

    # Ensure timestamp exists + convert safely
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])
    else:
        df["timestamp"] = pd.NaT

    return df

df = load_logs()

# -----------------------------
# Metrics Section
# -----------------------------
st.subheader("Key Metrics")

if not df.empty:

    total_requests = len(df)
    fake_requests = int(df["is_fake"].sum())
    real_requests = total_requests - fake_requests

    fake_ratio = fake_requests / total_requests if total_requests else 0
    indistinguishability_proxy = max(0.0, 1 - (abs(0.5 - fake_ratio) * 2))

    first_seen = df["timestamp"].min()

    first_fake = (
        df[df["is_fake"] == True]["timestamp"].min()
        if fake_requests > 0 else None
    )

    detection_latency_seconds = (
        (first_fake - first_seen).total_seconds()
        if first_fake is not None else None
    )

    fake_df = df[df["is_fake"] == True]

    dwell_seconds = (
        (fake_df["timestamp"].max() - fake_df["timestamp"].min()).total_seconds()
        if len(fake_df) >= 2 else None
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Requests", total_requests)
    col2.metric("Fake Key Usage", fake_requests)
    col3.metric("Real Key Usage", real_requests)
    col4.metric("Indistinguishability Proxy", f"{indistinguishability_proxy:.2f}")

    col5, col6 = st.columns(2)

    col5.metric(
        "Detection Latency (s)",
        "N/A" if detection_latency_seconds is None else f"{detection_latency_seconds:.1f}",
    )

    col6.metric(
        "Dwell Time (s)",
        "N/A" if dwell_seconds is None else f"{dwell_seconds:.1f}",
    )

else:
    st.warning("No data available yet.")

# -----------------------------
# Timeline Chart
# -----------------------------
st.subheader("Activity Timeline")

if not df.empty:
    timeline = df.groupby(df["timestamp"].dt.floor("min")).size()
    st.line_chart(timeline)

# -----------------------------
# Fake vs Real Distribution
# -----------------------------
st.subheader("Fake vs Real Key Usage")

if not df.empty:
    pie_data = pd.DataFrame({
        "Type": ["Fake", "Real"],
        "Count": [fake_requests, real_requests]
    })

    st.bar_chart(pie_data.set_index("Type"))

# -----------------------------
# Detailed Logs
# -----------------------------
st.subheader("Attacker Activity Logs")

if not df.empty:
    columns_to_show = [
        "timestamp",
        "session_id",
        "api_key",
        "endpoint",
        "method",
        "is_fake",
        "response_kind",
    ]

    existing_cols = [col for col in columns_to_show if col in df.columns]

    st.dataframe(df[existing_cols], use_container_width=True)

# -----------------------------
# Detection Insight
# -----------------------------
st.subheader("Detection Insight")

if not df.empty and fake_requests > 0:
    first_detection = df[df["is_fake"] == True]["timestamp"].min()
    st.success(f"Attacker detected at: {first_detection}")
else:
    st.info("No attacker activity detected yet.")

# -----------------------------
# Footer
# -----------------------------
st.markdown("---")
st.markdown("Built with using Honey Encryption + Sinkhole Architecture")