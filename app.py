"""Local Streamlit SOC dashboard: employees ranked by insider-threat risk. Run using start.sh."""
from pathlib import Path
import json
import os
import sqlite3
from datetime import datetime, timezone
import pandas as pd
import streamlit as st
from monitor.core import Engine, config, now
from monitor.demo import events as demo_events
from monitor.views import active_ranking, collector_health, employee_events, snapshot, unattributed_events
from monitor.lab_readiness import readiness
from monitor.brain.explain import explain_employee
from monitor.response import Responder, MODES

LEVEL_BADGE = {'high': '🔴 HIGH', 'medium': '🟠 MEDIUM', 'low': '🟢 LOW'}

st.set_page_config(page_title='Anomaly-Driven Active Defense Platform', layout='wide')
st.markdown('''<style>
.stApp {background: #0b1220; color: #e5edf8}
[data-testid=stMetric] {background: #142239; padding: 18px; border-radius: 10px}
h1 {color: #68d9ef; font-size: clamp(1.5rem, 3.2vw, 2.8rem); line-height: 1.2; overflow-wrap: anywhere; text-wrap: balance}
</style>''', unsafe_allow_html=True)
st.title('Development of an Anomaly-Driven Active Defense Platform Against Unauthorized Access and Credential Attacks')
st.caption('LOCAL SOC • Unsupervised insider-threat detection • Risk levels derived from normal behaviour • '
           'A high score is a deviation requiring investigation, not proof of intent')
mode = st.sidebar.radio('Data environment', ['Live monitoring', 'Demonstration'])
hours = st.sidebar.selectbox('Event window (hours)', [1, 24, 168, 8760], index=2)
st.sidebar.caption('The ranking shows employees active in this window, by their peak risk within it. '
                   'Default is 7 days. Refreshes every 3 seconds.')
try:
    settings = config(os.environ.get('SIX_CONFIG', 'config.local.json'))
except (ValueError, OSError) as exc:
    st.error(f'Configuration error: {exc}')
    st.stop()
data = Path(os.environ.get('SIX_DATA', 'data'))


def stamp(value, zone):
    if not value:
        return 'None yet'
    return datetime.fromtimestamp(value, timezone.utc).astimezone(zone).strftime('%Y-%m-%d %H:%M:%S')


def run_demo(engine):
    with engine.db:
        engine.db.execute('DELETE FROM events')
        engine.db.execute('DELETE FROM employee_risk')
    engine.event_count = 0
    prepared = [engine.prepare(e) for e in demo_events()]
    engine.ingest(prepared)


def ranking_frame(employees, directory, zone):
    rows = []
    for rank, e in enumerate(employees, 1):
        person = directory.employee(e['employee_id'])
        rows.append({
            'Rank': rank, 'Level': LEVEL_BADGE.get(e.get('peak_level', e['level']), e['level']),
            'Employee': e['employee_id'], 'Name': person.get('employee_name', ''),
            'Department': person.get('department', ''), 'Job title': person.get('job_title', ''),
            'Peak risk': round(e['peak_risk'], 4), 'Peak time': stamp(e.get('peak_ts'), zone),
            'Current risk': round(e['risk'], 4), 'Current level': LEVEL_BADGE.get(e['level'], e['level']),
            'Percentile vs normal': round(e['risk_percentile'], 1),
            'Last activity': stamp(e['last_ts'], zone), 'High-level events': e['high_events'], 'Events seen': e['events'],
        })
    return pd.DataFrame(rows)


def analysis_panel(engine, employee, zone):
    brain, directory = engine.brain, engine.directory
    recent = employee_events(engine, employee['employee_id'])
    report = explain_employee(brain, directory, employee, recent)
    st.subheader(f"AI analysis — {employee['employee_id']}")
    left, middle, right = st.columns(3)
    left.metric('Risk level', employee['level'].upper())
    middle.metric('Rolling risk score', f"{employee['risk']:.4f}")
    right.metric('Higher than normal employees', f"{employee['risk_percentile']:.1f}%")
    if employee.get('peak_ts') and employee.get('peak_level') != employee['level']:
        st.caption(f"Peak in window: {employee.get('peak_level', '').upper()} "
                   f"(risk {employee['peak_risk']:.4f}) at {stamp(employee['peak_ts'], zone)}. "
                   'Current risk is lower because recent activity has returned to normal; the peak keeps the incident visible.')
    st.markdown(report['summary'])
    if report['reasons']:
        st.markdown('**Why: the largest deviations from this employee\'s own normal behaviour**')
        st.markdown('\n'.join(f"- **{r['label']}** — {r['text']}" for r in report['reasons']))
    st.caption(report['caveat'])
    if recent:
        frame = pd.DataFrame(recent)
        frame['Time'] = [stamp(t, zone) for t in frame.ts]
        frame['Level'] = frame.level.map(LEVEL_BADGE)
        frame['Higher than normal events (%)'] = brain.event_percentile(frame.score.fillna(0)).round(1)
        chart = frame[['ts', 'score']].assign(time=pd.to_datetime(frame.ts, unit='s', utc=True)).set_index('time')[['score']]
        st.markdown('**Event anomaly scores over time**')
        st.line_chart(chart.rename(columns={'score': 'event anomaly score'}))
        st.markdown('**Recent events**')
        st.dataframe(frame[['Time', 'Level', 'score', 'Higher than normal events (%)', 'dst_service', 'dst_ip', 'protocol', 'port',
                            'bytes_in', 'bytes_out', 'response_ms', 'prev_hour', 'kind']].rename(columns={
                                'score': 'Anomaly score', 'dst_service': 'Service', 'dst_ip': 'Destination', 'protocol': 'Protocol',
                                'port': 'Port', 'bytes_in': 'Bytes in', 'bytes_out': 'Bytes out', 'response_ms': 'Response ms',
                                'prev_hour': 'Events prev. hour', 'kind': 'Kind'}),
                     hide_index=True, width='stretch')


MODE_LABEL = {'auto': 'Automatic', 'manual': 'Manual (analyst approves)', 'disabled': 'Disabled (kill-switch)'}


def response_write(path, action):
    """Run a response mutation on a short-lived writable engine, then refresh."""
    writable = Engine(path, settings)
    try:
        action(Responder(writable))
    finally:
        writable.close()


def response_section(engine, path, directory, brain, zone):
    responder = Responder(engine, directory)
    mode = responder.mode()
    active = responder.active_responses()
    st.subheader('Active defense — automatic response')
    high = brain.employee_boundaries_['high']
    st.caption(f"Score-triggered: a response fires when an employee's **peak** risk crosses the high boundary "
               f"({high:.4f}); medium never triggers. Actions are loopback-only and reversible: **block_ip** (the lab "
               "refuses that device IP and the collector marks its telemetry BLOCKED) and **end_session**. "
               "The trigger is the model's score, not a rule.")

    top = st.columns([2, 1, 1])
    choice = top[0].radio('Auto-response mode', list(MODES), index=list(MODES).index(mode),
                          format_func=MODE_LABEL.get, horizontal=True, key='resp_mode')
    if choice != mode:
        response_write(path, lambda r: r.set_mode(choice))
        st.rerun()
    if top[1].button('⛔ Kill-switch', help='Disable all automatic response immediately', disabled=mode == 'disabled'):
        response_write(path, lambda r: r.set_mode('disabled'))
        st.rerun()
    pending = [c for c in responder.candidates(brain)]
    if top[2].button(f'Respond to all HIGH ({len(pending)})', disabled=not pending or mode == 'disabled',
                     help='Apply block_ip + end_session to every employee over the high boundary'):
        response_write(path, lambda r: [r.respond(c['employee_id'], brain=r.engine.brain, peak_risk=c['peak_risk'],
                                                   created_by='analyst') for c in r.candidates(r.engine.brain)])
        st.rerun()

    if mode == 'manual' and pending:
        st.markdown('**Awaiting analyst decision — employees over the high boundary:**')
        for c in pending:
            cols = st.columns([3, 2, 1])
            person = directory.employee(c['employee_id'])
            cols[0].write(f"{c['employee_id']} — {person.get('employee_name','')} ({person.get('department','')})")
            cols[1].write(f"peak {c['peak_risk']:.3f} · {c['source_ip'] or 'no device IP'}")
            if cols[2].button('Respond', key=f"respond_{c['employee_id']}"):
                response_write(path, lambda r, e=c['employee_id'], pk=c['peak_risk']:
                               r.respond(e, brain=r.engine.brain, peak_risk=pk, created_by='analyst'))
                st.rerun()

    if active:
        st.markdown('**Active responses** (reversible):')
        for r in active:
            cols = st.columns([3, 3, 1])
            person = directory.employee(r['employee_id'])
            acts = ', '.join(json.loads(r['actions']))
            cols[0].write(f"🛡️ {r['employee_id']} — {person.get('employee_name','')} · `{r['source_ip']}`")
            cols[0].caption(f"{acts} · by {r['created_by']} · {stamp(r['created_ts'], zone)}")
            cols[1].caption(r['reason'] or '')
            if cols[2].button('Unblock / Reinstate', key=f"revert_{r['id']}"):
                response_write(path, lambda rr, rid=r['id']: rr.revert(rid))
                st.rerun()
    else:
        st.caption('No active responses.')

    history = responder.all_responses()
    if history:
        with st.expander(f'Response history ({len(history)}) and audit log'):
            frame = pd.DataFrame(history)
            frame['When'] = [stamp(t, zone) if pd.notna(t) else '' for t in frame.created_ts]
            frame['Reverted'] = [stamp(t, zone) if pd.notna(t) else '' for t in frame.reverted_ts]
            frame['Actions'] = frame.actions.map(lambda a: ', '.join(json.loads(a)))
            st.dataframe(frame[['When', 'employee_id', 'source_ip', 'Actions', 'peak_risk', 'reason',
                                'created_by', 'status', 'Reverted', 'reverted_by']].rename(
                columns={'employee_id': 'Employee', 'source_ip': 'IP', 'peak_risk': 'Peak risk',
                         'reason': 'Reason', 'created_by': 'By', 'status': 'Status', 'reverted_by': 'Reverted by'}),
                hide_index=True, width='stretch')
            audit = responder.audit_log()
            if audit:
                adf = pd.DataFrame(audit)
                adf['When'] = [stamp(t, zone) for t in adf.ts]
                st.markdown('**Audit log**')
                st.dataframe(adf[['When', 'action', 'employee_id', 'actor', 'detail']].rename(
                    columns={'action': 'Action', 'employee_id': 'Employee', 'actor': 'Actor', 'detail': 'Detail'}),
                    hide_index=True, width='stretch')


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
    try:
        try:
            brain, directory = engine.brain, engine.directory
        except (OSError, ValueError) as exc:
            st.error(f'Detection model unavailable: {exc}')
            return
        from zoneinfo import ZoneInfo
        zone = ZoneInfo(directory.timezone)
        statuses = []
        if mode == 'Demonstration':
            st.info('DEMONSTRATION — an unlabelled replay of 48 hours of synthetic organisation activity, isolated from '
                    'live monitoring. Each run replaces the previous demonstration data.')
            if st.button('Run demonstration replay'):
                run_demo(engine)
        else:
            health = collector_health(engine, settings['poll_seconds'])
            statuses = health.get('sources', [])
            if health['status'] == 'RUNNING':
                st.success(f"Background collector: RUNNING • model {health.get('model_version', 'unknown')} • independent of the browser")
            else:
                st.warning('Background collector: ' + health['status'])
            if health.get('error'):
                st.error(health['error'])
            last = health.get('last_event') or json.loads(engine.state('last_event') or 'null')
            st.caption('Last heartbeat: ' + stamp(health.get('heartbeat'), zone) +
                       ' | Last event: ' + stamp(last.get('event_ts') if last else None, zone) +
                       ' | Last processed: ' + stamp(last.get('processed_ts') if last else None, zone) + f' ({directory.timezone})')
        cutoff = now() - hours * 3600
        engine.db.execute('BEGIN')
        try:
            view = snapshot(engine, cutoff)
        finally:
            engine.db.rollback()
        employees, counts = view['employees'], view['counts']
        ranked = active_ranking(engine, brain, cutoff)
        cols = st.columns(5)
        for col, label, value in zip(cols, ['Employees monitored', 'High risk', 'Medium risk', f'Events scored ({hours} h)', f'High-level events ({hours} h)'],
                                     [len(employees), sum(e['peak_level'] == 'high' for e in ranked), sum(e['peak_level'] == 'medium' for e in ranked),
                                      counts['scored'], counts['high']]):
            col.metric(label, value)

        st.subheader('Employee risk ranking')
        b = brain.employee_boundaries_
        st.caption(f"Ranked by **peak** risk reached in the last {hours} h, so an employee who spiked then went quiet stays "
                   f"visible; current risk and the peak's time are shown too. Risk = time-decayed mean of an employee's recent "
                   f"event anomaly scores (half-life {brain.risk_half_life_hours:g} h); event counts do not raise it. Levels come "
                   f"from normal employee behaviour in calibration: medium ≥ {b['medium']:.4f} (95th percentile), "
                   f"high ≥ {b['high']:.4f} (99th percentile). The Level badge is the peak level. Select a row to open its AI analysis.")
        if not ranked:
            st.info('No attributed employee activity in this window yet.')
        else:
            frame = ranking_frame(ranked, directory, zone)
            selection = st.dataframe(frame, hide_index=True, width='stretch', on_select='rerun', selection_mode='single-row',
                                     key='employee_table', height=420)
            options = list(frame.Employee)
            chosen = tuple(selection.selection.rows) if selection is not None else ()
            if chosen and chosen != st.session_state.get('_applied_selection'):
                st.session_state['_applied_selection'] = chosen
                st.session_state['analyse_employee'] = options[chosen[0]]
            if st.session_state.get('analyse_employee') not in options:
                st.session_state['analyse_employee'] = options[0]
            employee_id = st.selectbox('Employee to analyse', options, key='analyse_employee',
                                       format_func=lambda e: f"{e} — {directory.employee(e).get('employee_name', '')}")
            st.divider()
            analysis_panel(engine, next(e for e in ranked if e['employee_id'] == employee_id), zone)

        if mode == 'Live monitoring':
            st.divider()
            response_section(engine, path, directory, brain, zone)

        st.divider()
        left, right = st.columns(2)
        with left:
            st.subheader('Scored events by level')
            if view['timeline']:
                timeline = pd.DataFrame(view['timeline'])
                timeline['time'] = pd.to_datetime(timeline.ts, unit='s', utc=True)
                st.line_chart(timeline.pivot(index='time', columns='level', values='events').fillna(0))
            else:
                st.caption('No scored events in this window.')
        with right:
            st.subheader('Most unusual events in window')
            if view['elevated']:
                elevated = pd.DataFrame(view['elevated'])
                elevated['Time'] = [stamp(t, zone) for t in elevated.ts]
                elevated['Level'] = elevated.level.map(LEVEL_BADGE)
                st.dataframe(elevated[['Time', 'Level', 'employee_id', 'dst_service', 'score']].rename(
                    columns={'employee_id': 'Employee', 'dst_service': 'Service', 'score': 'Anomaly score'}),
                    hide_index=True, width='stretch', height=300)
            else:
                st.caption('No medium- or high-level events in this window.')
        with st.expander(f"Unattributed events ({counts['unattributed']}) — source address not mapped to an employee device"):
            rows = unattributed_events(engine, cutoff)
            if rows:
                frame = pd.DataFrame(rows)
                frame['Time'] = [stamp(t, zone) for t in frame.ts]
                st.dataframe(frame[['Time', 'source', 'kind', 'ip', 'dst_service', 'score', 'level', 'message']], hide_index=True, width='stretch')
            else:
                st.caption('None.')
        if mode == 'Live monitoring':
            with st.expander('Collector, sources and lab health'):
                lab_rows = readiness(settings, collector_health(engine, settings['poll_seconds']))
                if lab_rows:
                    st.dataframe(pd.DataFrame(lab_rows), hide_index=True, width='stretch')
                if statuses:
                    st.dataframe(pd.DataFrame(statuses), hide_index=True, width='stretch')
                else:
                    st.warning('No live sources configured. Configure readable auth logs, HTTP/firewall logs or behavioural JSONL telemetry.')
    finally:
        engine.close()


dashboard()
