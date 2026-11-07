"""Local Streamlit SOC dashboard. Run using start.sh."""
from pathlib import Path
import os
import pandas as pd
import streamlit as st
from monitor.core import Engine, CATEGORIES, config, collect, now
from monitor.demo import events

st.set_page_config(page_title='Six-Attack SOC', page_icon='🛡️', layout='wide')
st.markdown('''<style>
.stApp {background: #0b1220; color: #e5edf8}
[data-testid=stMetric] {background: #142239; padding: 18px; border-radius: 10px}
h1 {color: #68d9ef}
</style>''', unsafe_allow_html=True)
st.title('🛡️ Six-Attack Security Monitor')
st.caption('LOCAL SOC • Rule-based indicators • Possible suspicious activity requires investigation')
mode = st.sidebar.radio('Data environment', ['Demonstration', 'Live monitoring'])
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
    engine = Engine(data / ('demo.db' if mode == 'Demonstration' else 'live.db'), settings)
    try:
        if mode == 'Demonstration':
            st.info('SIMULATED DATA — isolated from live monitoring. Each run replaces the previous demo dataset.')
            if st.button('Run six-category demonstration'):
                with engine.db:
                    engine.db.execute('DELETE FROM alerts')
                    engine.db.execute('DELETE FROM events')
                for event in events():
                    engine.process(event)
            statuses = [dict(source='Built-in demonstration', status='Available; no attacks executed')]
        else:
            statuses = collect(engine)
            st.caption('Collection runs during refresh. JSONL supplies HTTP/firewall telemetry; auth logs supply SSH/sudo events; file entries monitor content hashes.')
        cutoff = now() - hours * 3600
        alerts = [a for a in engine.rows('alerts') if a['event_ts'] >= cutoff and (category == 'All' or a['attack'] == category)]
        all_events = engine.rows('events')
        ids = {a['event_id'] for a in alerts}
        ev = [e for e in all_events if e['ts'] >= cutoff and (category == 'All' or e['id'] in ids)]
        normal = sum(e['status'] == 'NORMAL' for e in ev)
        columns = st.columns(4)
        for col, label, value in zip(columns, ['Total Events', 'Normal Events', 'Abnormal Events', 'Total Security Alerts'], [len(ev), normal, len(ev)-normal, len(alerts)]):
            col.metric(label, value)
        left, right = st.columns(2)
        with left:
            st.subheader('Attack Distribution')
            if alerts:
                st.bar_chart(pd.DataFrame(alerts)['attack'].value_counts())
            else:
                st.caption('No alerts in this selection.')
        with right:
            st.subheader('Security Events Timeline')
            if ev:
                frame = pd.DataFrame(ev)
                frame['time'] = pd.to_datetime(frame.ts, unit='s', utc=True).dt.floor('min')
                st.line_chart(frame.groupby(['time', 'status']).size().unstack(fill_value=0))
        st.subheader('Recent Alerts • HIGH 🔴 / MEDIUM 🟠')
        if alerts:
            frame = pd.DataFrame(alerts)
            frame['detected_at_utc'] = pd.to_datetime(frame.ts, unit='s', utc=True).astype(str)
            st.dataframe(frame[['attack', 'detected_at_utc', 'ip', 'severity', 'rule', 'description', 'action']], width='stretch', hide_index=True)
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
            configured = {s.get('format', 'jsonl') for s in settings['sources']}
            coverage = [dict(category=name, required_source=requirement, configured='Configured (verify event coverage)' if ok else 'Not configured') for name, requirement, ok in [
                (CATEGORIES[0], 'Auth log or normalized ssh_failed events', bool(configured)),
                (CATEGORIES[1], 'JSONL connection telemetry with destination ports', 'jsonl' in configured),
                (CATEGORIES[2], 'JSONL HTTP request telemetry', 'jsonl' in configured),
                (CATEGORIES[3], 'JSONL HTTP request telemetry', 'jsonl' in configured),
                (CATEGORIES[4], 'Configured test file paths', bool(settings['files'])),
                (CATEGORIES[5], 'Auth log or normalized privilege events', bool(configured))]]
            st.dataframe(pd.DataFrame(coverage), hide_index=True, width='stretch')
        st.caption('Time filters use event time. Category filtering shows alert-linked events; suppressed repeat indicators remain available under All.')
    finally:
        engine.close()


dashboard()
