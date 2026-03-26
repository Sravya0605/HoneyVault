import os
import requests
import streamlit as st
import pandas as pd
import altair as alt
from pymongo import MongoClient

# -----------------------------
# Config
# -----------------------------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "honeyvault")
API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
logs_collection = db["logs"]

st.set_page_config(page_title="HoneyVault Dashboard", layout="wide")

st.title("HoneyVault Security Dashboard")
st.markdown("### Deception-Driven Encryption Monitoring System")


def fetch_api_json(path: str):
   if not ADMIN_API_TOKEN:
      return None
   try:
      response = requests.get(
         f"{API_BASE_URL}{path}",
         headers={"x-api-token": ADMIN_API_TOKEN},
         timeout=3,
      )
      if response.status_code == 200:
         return response.json()
   except Exception:
      return None
   return None


def load_logs():
   logs = list(logs_collection.find().sort("timestamp", -1))
   for log in logs:
      log["_id"] = str(log["_id"])
   return pd.DataFrame(logs)


df = load_logs()
metrics_summary = fetch_api_json("/api/metrics/summary")
metrics_integrity = fetch_api_json("/api/metrics/integrity")
metrics_slo = fetch_api_json("/api/metrics/slo")

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

   df["timestamp"] = pd.to_datetime(df["timestamp"])
   first_seen = df["timestamp"].min()
   first_fake = df[df["is_fake"] == True]["timestamp"].min() if fake_requests > 0 else None
   detection_latency_seconds = (
      (first_fake - first_seen).total_seconds() if first_fake is not None else None
   )

   fake_df = df[df["is_fake"] == True]
   dwell_seconds = (
      (fake_df["timestamp"].max() - fake_df["timestamp"].min()).total_seconds()
      if len(fake_df) >= 2
      else None
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
# Runtime Security Panels
# -----------------------------
st.subheader("Runtime Security")
if metrics_slo:
   slo_col1, slo_col2, slo_col3, slo_col4 = st.columns(4)
   slo_col1.metric("SLO Target", metrics_slo.get("availability_target", "N/A"))
   slo_col2.metric("Availability", metrics_slo.get("availability_observed", "N/A"))
   slo_col3.metric("Error Budget Remaining", metrics_slo.get("error_budget_remaining_ratio", "N/A"))
   slo_col4.metric("Avg Latency (ms)", metrics_slo.get("avg_latency_ms", "N/A"))

if metrics_integrity:
   int_col1, int_col2, int_col3 = st.columns(3)
   int_col1.metric("Log Integrity Status", metrics_integrity.get("status", "unknown"))
   int_col2.metric("Broken Chain Links", metrics_integrity.get("broken_links", 0))
   int_col3.metric("Validated Chain Logs", metrics_integrity.get("validated_logs", 0))

if not metrics_slo and not metrics_integrity:
   st.info("Runtime panels unavailable. Set ADMIN_API_TOKEN for dashboard process to enable metrics API access.")

# -----------------------------
# Timeline Chart
# -----------------------------
st.subheader("Activity Timeline")
if not df.empty:
   timeline_df = (
      df.assign(minute=df["timestamp"].dt.floor("min"))
      .groupby("minute", as_index=False)
      .size()
      .rename(columns={"size": "count"})
   )

   timeline_chart = (
      alt.Chart(timeline_df)
      .mark_line(point=True)
      .encode(
         x=alt.X("minute:T", title="Time"),
         y=alt.Y("count:Q", title="Requests", scale=alt.Scale(domainMin=0)),
         tooltip=["minute:T", "count:Q"],
      )
      .properties(height=280)
   )
   st.altair_chart(timeline_chart, use_container_width=True)

# -----------------------------
# Fake vs Real Distribution
# -----------------------------
st.subheader("Fake vs Real Key Usage")
if not df.empty:
   ratio_df = pd.DataFrame(
      {
         "type": ["Fake", "Real"],
         "count": [fake_requests, real_requests],
      }
   )

   ratio_chart = (
      alt.Chart(ratio_df)
      .mark_bar()
      .encode(
         x=alt.X("type:N", title="Type"),
         y=alt.Y("count:Q", title="Count", scale=alt.Scale(domainMin=0)),
         color=alt.Color("type:N", legend=None),
         tooltip=["type:N", "count:Q"],
      )
      .properties(height=260)
   )
   st.altair_chart(ratio_chart, use_container_width=True)

# -----------------------------
# Detailed Logs
# -----------------------------
st.subheader("Attacker Activity Logs")
if not df.empty:
   if "api_key_masked" not in df.columns and "api_key" in df.columns:
      df["api_key_masked"] = df["api_key"]
   if "api_key_masked" not in df.columns:
      df["api_key_masked"] = "unknown"

   display_df = df[
      [
         "timestamp",
         "session_id",
         "api_key_masked",
         "endpoint",
         "method",
         "is_fake",
         "response_kind",
      ]
   ]
   st.dataframe(display_df, use_container_width=True)

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