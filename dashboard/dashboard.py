import streamlit as st
import pandas as pd
from pymongo import MongoClient
import plotly.express as px
import time

# -----------------------------
# Simple Auth System
# -----------------------------
def login():
    st.markdown("""
        <style>
        .login-box {
            background-color: #111;
            padding: 30px;
            border-radius: 15px;
            border: 1px solid #333;
            max-width: 400px;
            margin: auto;
            margin-top: 100px;
        }
        .stTextInput > div > div > input {
            background-color: #222;
            color: white;
        }
        </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="login-box">', unsafe_allow_html=True)
    st.title("HoneyVault Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state["authenticated"] = True
            st.success("Login successful")
            st.rerun()
        else:
            st.error("Invalid credentials")

    st.markdown("</div>", unsafe_allow_html=True)


# Initialize session
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

# If not logged in → show login page
if not st.session_state["authenticated"]:
    login()
    st.stop()

# -----------------------------
# Config
# -----------------------------
MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "honeyvault"

st.set_page_config(
    page_title="HoneyVault Dashboard",
    layout="wide"
)

# -----------------------------
# Custom Styling
# -----------------------------
st.markdown("""
<style>
.block-container {
    padding-top: 1rem;
}
.metric-card {
    background-color: #111;
    padding: 15px;
    border-radius: 12px;
    border: 1px solid #333;
}
</style>
""", unsafe_allow_html=True)

st.title("HoneyVault Threat Intelligence Dashboard")
st.markdown("Deception-Driven Encryption Monitoring System")

# -----------------------------
# Mongo Connection
# -----------------------------
@st.cache_resource
def get_db():
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.server_info()
        return client[DB_NAME]
    except Exception as e:
        st.error(f"MongoDB connection failed: {e}")
        return None

db = get_db()

# -----------------------------
# Load Logs
# -----------------------------
@st.cache_data(ttl=2)
def load_logs():
    if db is None:
        return pd.DataFrame()

    logs = list(db["logs"].find().sort("timestamp", -1))

    if not logs:
        return pd.DataFrame()

    for log in logs:
        log["_id"] = str(log.get("_id", ""))
        log["is_fake"] = bool(log.get("is_fake", False))

    df = pd.DataFrame(logs)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])
    else:
        df["timestamp"] = pd.Timestamp.now()

    return df

# -----------------------------
# Load Stats
# -----------------------------
def load_stats():
    if db is None:
        return 0, 0

    vaults = db["vaults"].count_documents({})
    logs = db["logs"].count_documents({})
    return vaults, logs

# -----------------------------
# Sidebar Controls
# -----------------------------
st.sidebar.header("Controls")

refresh = st.sidebar.checkbox("Auto Refresh", value=False)
refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 2, 10, 5)

show_fake = st.sidebar.checkbox("Show Fake", True)
show_real = st.sidebar.checkbox("Show Real", True)

if st.sidebar.button("Manual Refresh"):
    st.cache_data.clear()

# -----------------------------
# Load Data
# -----------------------------
df = load_logs()
vault_count, log_count = load_stats()

# -----------------------------
# Filters
# -----------------------------
filtered_df = df.copy()

if not show_fake:
    filtered_df = filtered_df[filtered_df["is_fake"] == False]

if not show_real:
    filtered_df = filtered_df[filtered_df["is_fake"] == True]

# -----------------------------
# System Overview
# -----------------------------
st.subheader("System Overview")

colA, colB = st.columns(2)
colA.metric("Vaults Stored", vault_count)
colB.metric("Logs Collected", log_count)

# -----------------------------
# Metrics + Intelligence
# -----------------------------
st.subheader("Threat Metrics")

if not filtered_df.empty:

    total_requests = len(filtered_df)
    fake_requests = int(filtered_df["is_fake"].sum())
    real_requests = total_requests - fake_requests

    fake_ratio = fake_requests / total_requests if total_requests else 0
    score = max(0.0, 1 - (abs(0.5 - fake_ratio) * 2))

    # Threat classification
    if fake_ratio > 0.7:
        severity = "High Threat"
    elif fake_ratio > 0.3:
        severity = "Suspicious"
    else:
        severity = "Normal"

    first_seen = filtered_df["timestamp"].min()
    first_fake = (
        filtered_df[filtered_df["is_fake"] == True]["timestamp"].min()
        if fake_requests > 0 else None
    )

    detection_latency = (
        (first_fake - first_seen).total_seconds()
        if first_fake is not None else None
    )

    fake_df = filtered_df[filtered_df["is_fake"] == True]

    dwell_time = (
        (fake_df["timestamp"].max() - fake_df["timestamp"].min()).total_seconds()
        if len(fake_df) >= 2 else None
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Requests", total_requests)
    col2.metric("Fake Activity", fake_requests, delta=f"{fake_ratio:.2%}")
    col3.metric("Real Activity", real_requests)
    col4.metric("Threat Level", severity)

    col5, col6 = st.columns(2)
    col5.metric(
        "Detection Latency (s)",
        "N/A" if detection_latency is None else f"{detection_latency:.1f}",
    )

    col6.metric(
        "Dwell Time (s)",
        "N/A" if dwell_time is None else f"{dwell_time:.1f}",
    )

else:
    st.warning("No data available.")

# -----------------------------
# Timeline
# -----------------------------
st.subheader("Activity Timeline")

if not filtered_df.empty:
    timeline = filtered_df.copy()
    timeline["minute"] = timeline["timestamp"].dt.floor("min")

    grouped = timeline.groupby(["minute", "is_fake"]).size().reset_index(name="count")

    fig = px.line(
        grouped,
        x="minute",
        y="count",
        color="is_fake",
        markers=True,
        title="Requests over Time"
    )

    fig.update_layout(template="plotly_dark")
    st.plotly_chart(fig, use_container_width=True)

# -----------------------------
# Distribution
# -----------------------------
st.subheader("Fake vs Real Distribution")

if not filtered_df.empty:
    pie = px.pie(
        names=["Fake", "Real"],
        values=[fake_requests, real_requests],
        color=["Fake", "Real"],
        color_discrete_map={
            "Fake": "red",
            "Real": "green"
        }
    )

    pie.update_layout(template="plotly_dark")
    st.plotly_chart(pie, use_container_width=True)

# -----------------------------
# Behavior Insights
# -----------------------------
st.subheader("Behavior Insights")

if not filtered_df.empty:

    col1, col2 = st.columns(2)

    with col1:
        st.write("Top Endpoints Targeted")
        st.bar_chart(filtered_df["endpoint"].value_counts().head(5))

    with col2:
        st.write("HTTP Methods Used")
        st.bar_chart(filtered_df["method"].value_counts())

# -----------------------------
# Logs Table (Styled)
# -----------------------------
st.subheader("Activity Logs")

if not filtered_df.empty:

    def highlight_fake(row):
        return ['background-color: #330000' if row.is_fake else '' for _ in row]

    columns = [
        "timestamp",
        "session_id",
        "endpoint",
        "method",
        "is_fake",
        "response_kind",
    ]

    existing = [col for col in columns if col in filtered_df.columns]

    styled_df = filtered_df[existing].style.apply(highlight_fake, axis=1)

    st.dataframe(styled_df, use_container_width=True)

# -----------------------------
# Live Feed
# -----------------------------
st.subheader("Live Activity Feed")

if not filtered_df.empty:
    latest = filtered_df.head(10)

    for _, row in latest.iterrows():
        st.write(
            f"{row['timestamp']} | {row['endpoint']} | {row['method']} | {'FAKE' if row['is_fake'] else 'REAL'}"
        )

# -----------------------------
# Detection Insight
# -----------------------------
st.subheader("Detection Insight")

if not filtered_df.empty and fake_requests > 0:
    first_detection = filtered_df[filtered_df["is_fake"] == True]["timestamp"].min()

    st.success(f"""
    Attacker detected at {first_detection}

    Fake interactions: {fake_requests}
    Detection latency: {detection_latency:.2f} seconds
    Behavior indicates probing or malicious interaction.
    """)
else:
    st.info("No attacker activity detected.")

# -----------------------------
# Footer
# -----------------------------
st.markdown("---")
st.markdown("HoneyVault Monitoring System")

# -----------------------------
# Auto Refresh
# -----------------------------
if refresh:
    st.sidebar.info(f"Refreshing every {refresh_interval} seconds")
    time.sleep(refresh_interval)
    st.rerun()