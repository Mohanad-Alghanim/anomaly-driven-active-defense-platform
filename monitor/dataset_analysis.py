"""Synthetic dataset analysis; isolated from live and demonstration databases."""
from pathlib import Path

import pandas as pd
import streamlit as st


DATASET_PATH = Path(__file__).resolve().parent.parent / "data" / "datasets" / "Anomaly_Defense_Team_Dataset_FIXED1.xlsx"


@st.cache_data(show_spinner="Loading dataset...")
def load_dataset(path: str, modified: float):
    raw = pd.read_excel(path, sheet_name="Raw_Events")
    model = pd.read_excel(path, sheet_name="Model_Ready")
    rules = pd.read_excel(path, sheet_name="Detection_Rules")
    return raw, model, rules


def render_dataset_analysis():
    st.header("Dataset Analysis")
    st.warning(
        "SYNTHETIC DATA ONLY — all records in this workbook are simulated. "
        "They are not live security events or proof of real attacks."
    )

    if not DATASET_PATH.is_file():
        st.error(f"Dataset file not found: {DATASET_PATH}")
        return

    try:
        raw, model, rules = load_dataset(
            str(DATASET_PATH), DATASET_PATH.stat().st_mtime
        )
    except Exception as exc:
        st.error(f"Could not load dataset: {exc}")
        return

    total = len(raw)
    anomalies = int((raw["ground_truth_label"] == "anomaly").sum())
    normal = int((raw["ground_truth_label"] == "normal").sum())
    anomaly_rate = (anomalies / total * 100) if total else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Events", f"{total:,}")
    c2.metric("Normal Events", f"{normal:,}")
    c3.metric("Anomaly Events", f"{anomalies:,}")
    c4.metric("Anomaly Rate", f"{anomaly_rate:.1f}%")

    st.subheader("Attack Category Distribution")
    attack_counts = (
        raw.loc[raw["attack_category"].ne("none"), "attack_category"]
        .value_counts()
        .rename_axis("Attack Category")
        .to_frame("Records")
    )
    left, right = st.columns(2)
    with left:
        st.bar_chart(attack_counts)
    with right:
        st.dataframe(attack_counts, width="stretch")

    st.subheader("Event Activity")
    activity = raw.copy()
    activity["event_date"] = pd.to_datetime(activity["event_date"], errors="coerce")
    activity["hour_of_day"] = pd.to_numeric(
        activity["hour_of_day"], errors="coerce"
    )
    hourly = (
        activity.groupby("hour_of_day", dropna=True)
        .size()
        .rename("Events")
        .to_frame()
        .sort_index()
    )
    st.bar_chart(hourly)

    st.subheader("Team Member Summary")
    team = (
        raw.groupby("team_member", dropna=False)
        .agg(
            Total_Events=("event_id", "count"),
            Anomaly_Events=("ground_truth_label", lambda s: (s == "anomaly").sum()),
            Normal_Events=("ground_truth_label", lambda s: (s == "normal").sum()),
        )
        .sort_values("Total_Events", ascending=False)
    )
    st.dataframe(team, width="stretch")

    st.subheader("Filter Dataset Records")
    categories = ["All", *sorted(raw["attack_category"].dropna().unique().tolist())]
    members = ["All", *sorted(raw["team_member"].dropna().unique().tolist())]
    f1, f2 = st.columns(2)
    selected_category = f1.selectbox("Attack Category", categories)
    selected_member = f2.selectbox("Team Member", members)

    filtered = raw.copy()
    if selected_category != "All":
        filtered = filtered[filtered["attack_category"] == selected_category]
    if selected_member != "All":
        filtered = filtered[filtered["team_member"] == selected_member]

    st.caption(f"Showing {len(filtered):,} of {total:,} records")
    st.dataframe(filtered, width="stretch", hide_index=True)

    with st.expander("Model-Ready Dataset"):
        st.caption(
            "Feature table supplied with the workbook. This view does not train "
            "or evaluate a machine-learning model."
        )
        st.dataframe(model, width="stretch", hide_index=True)

    with st.expander("Documented Detection Rules"):
        st.dataframe(rules, width="stretch", hide_index=True)
