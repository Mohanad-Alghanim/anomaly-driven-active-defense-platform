"""Local Streamlit SOC dashboard. Run using start.sh."""
from pathlib import Path
import os
import sqlite3
from datetime import datetime, timezone
import pandas as pd
import streamlit as st
from monitor.core import Engine, CATEGORIES, config, now
from monitor.demo import events
from monitor.views import collector_health, coverage, snapshot
from monitor.lab_readiness import readiness

st.set_page_config(page_title='Anomaly-Driven Active Defense Platform', layout='wide')
st.markdown('''<style>
.stApp {background: #0b1220; color: #e5edf8}
[data-testid=stMetric] {background: #142239; padding: 18px; border-radius: 10px}
h1 {color: #68d9ef; font-size: clamp(1.5rem, 3.2vw, 2.8rem); line-height: 1.2; overflow-wrap: anywhere; text-wrap: balance}
</style>''', unsafe_allow_html=True)
st.title('Development of an Anomaly-Driven Active Defense Platform Against Unauthorized Access and Credential Attacks')
st.caption('LOCAL SOC • Rule-based indicators • Possible suspicious activity requires investigation')
mode = st.sidebar.radio('Data environment', ['Live monitoring', 'Demonstration'])
category = st.sidebar.selectbox('Attack category', ['All', *CATEGORIES])
hours = st.sidebar.selectbox('Time range (hours)', [1, 24, 168, 8760], index=1)
st.sidebar.caption('Refreshes every 3 seconds while this dashboard is open.')
try:
    settings = config(os.environ.get('SIX_CONFIG', 'config.local.json'))
except (ValueError, OSError) as exc:
    st.error(f'Configuration error: {exc}')
    st.stop()
data = Path(os.environ.get('SIX_DATA', 'data'))


@st.fragment(run_every=3)
def dashboard():
    path = data / ('demo.db' if mode == 'Demonstration' else 'live.db')
    if mode == 'Live monitoring' and not path.exists():
        st.warning('Collector not started. Use the installed Active Defense Platform — Start Monitoring launcher for one-time setup.')
        engine = Engine(':memory:', settings)
    else:
        try:
            engine = Engine(path, settings, readonly=mode == 'Live monitoring')
        except sqlite3.Error as exc:
            st.error('Database unavailable: ' + str(exc))
            return
    if mode == 'Live monitoring' and engine.db.execute('PRAGMA user_version').fetchone()[0] < 2 and path.exists():
        st.warning('Database upgrade pending. Start the upgraded collector to migrate existing data safely.')
        engine.close()
        return
    try:
        if mode == 'Demonstration':
            st.info('SIMULATED DATA — isolated from live monitoring. Each run replaces the previous demo dataset.')
            if st.button('Run detection demonstration'):
                with engine.db:
                    engine.db.execute('DELETE FROM matches')
                    engine.db.execute('DELETE FROM alerts')
                    engine.db.execute('DELETE FROM events')
                engine.event_count = 0
                for event in events():
                    engine.process(event)
            statuses = [dict(source='Built-in demonstration', status='Available; no attacks executed')]
        else:
            health = collector_health(engine, settings['poll_seconds'])
            statuses = health.get('sources', [])
            status = health['status']
            if status == 'RUNNING':
                st.success('Background collector: RUNNING • independent of Firefox')
            else:
                st.warning('Background collector: ' + status)
            if health.get('error'):
                st.error(health['error'])
            st.subheader('Detection & Monitoring Readiness')
            st.caption('Target/source health is separate from live validation. Unit tests and demonstration data never mark a lab category verified.')
            st.dataframe(pd.DataFrame(readiness(settings, health)), hide_index=True, width='stretch')
            last = health.get('last_event')
            if last is None:
                import json
                last = json.loads(engine.state('last_event') or 'null')
            def stamp(value):
                return datetime.fromtimestamp(value, timezone.utc).isoformat() if value else 'None yet'
            st.caption('Last heartbeat: ' + stamp(health.get('heartbeat')) +
                       ' | Last successful event: ' + stamp(last.get('event_ts') if last else None) +
                       ' | Last processed: ' + stamp(last.get('processed_ts') if last else None))
        cutoff = now() - hours * 3600
        engine.db.execute('BEGIN')
        try:
            view = snapshot(engine, cutoff, category)
        finally:
            engine.db.rollback()
        alerts, ev = view['alerts'], view['events']
        total, normal, abnormal = view['counts']
        columns = st.columns(4)
        for col, label, value in zip(columns, ['Total Events', 'Normal Events', 'Abnormal Events', 'Total Security Alerts'], [total, normal, abnormal, view['total_alerts']]):
            col.metric(label, value)
        left, right = st.columns(2)
        with left:
            st.subheader('Attack Distribution')
            if alerts:
                st.bar_chart(pd.DataFrame(view['distribution']).set_index('attack'))
            else:
                st.caption('No alerts in this selection.')
        with right:
            st.subheader('Security Events Timeline')
            if view['timeline']:
                frame = pd.DataFrame(view['timeline'])
                frame['time'] = pd.to_datetime(frame.ts, unit='s', utc=True)
                st.line_chart(frame.pivot(index='time', columns='status', values='events').fillna(0))
        st.subheader('Recent Alerts • HIGH 🔴 / MEDIUM 🟠')
        if alerts:
            frame = pd.DataFrame(alerts)
            frame['event_at_utc'] = pd.to_datetime(frame.event_ts, unit='s', utc=True).astype(str)
            frame['detected_at_utc'] = pd.to_datetime(frame.ts, unit='s', utc=True).astype(str)
            st.dataframe(frame[['attack', 'event_at_utc', 'detected_at_utc', 'ip', 'source_port', 'dst_ip', 'dst_host', 'dst_port', 'status', 'severity', 'rule', 'description', 'action']], width='stretch', hide_index=True)
        else:
            st.caption('No alerts.')
        st.subheader('Event Details')
        if ev:
            selected = st.selectbox('Select event', range(len(ev)), format_func=lambda i: f"{ev[i]['status']} | {ev[i]['kind']} | {ev[i]['message'][:70]}")
            st.json(ev[selected])
        st.subheader('Input Source Status')
        if statuses:
            st.dataframe(pd.DataFrame(statuses), hide_index=True, width='stretch')
        else:
            st.warning('No live sources configured. Configure readable auth logs, normalized HTTP/firewall logs, and test files.')
        if mode == 'Live monitoring':
            st.dataframe(pd.DataFrame(coverage(settings, statuses)), hide_index=True, width='stretch')
        st.caption('Time filters use event time. Details show up to 1,000 recent records; counts and charts include the full selection. Category filters include suppressed matching events.')
    finally:
        engine.close()


dashboard()
