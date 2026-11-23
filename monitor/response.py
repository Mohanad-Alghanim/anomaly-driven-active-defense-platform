"""Active defense: score-triggered, bounded, reversible, audited responses.

The trigger is the model's own output, never a hand-written rule: when an employee's
PEAK rolling risk crosses the data-derived HIGH boundary (brain.employee_boundaries_
['high']), a response is proposed. MEDIUM never triggers. In 'auto' mode the response
is applied automatically; in 'manual' mode it waits for the analyst; 'disabled' is the
kill-switch (nothing new fires, existing responses remain until reverted).

Two actions, both loopback-only and reversible:
  * block_ip    — add the IP of the device that raised the employee's risk to
                  runtime/lab/enforcement.json. The
                  loopback lab target honours this list (403) and the collector marks
                  any further telemetry from that IP as BLOCKED, so it no longer raises
                  risk. No real host firewall is touched.
  * end_session — mark the employee's lab session ended (same enforcement file); the
                  lab refuses their requests until reinstated.

Every response and every manual action is written to the responses and response_audit
tables. Nothing here scores events or defines a detection threshold.
"""
import json
import uuid
from pathlib import Path

from .core import now
from .lab_setup import atomic_json

ACTIONS = ('block_ip', 'end_session')
MODES = ('auto', 'manual', 'disabled')
DEFAULT_MODE = 'manual'


class Responder:
    def __init__(self, engine, directory=None):
        self.engine = engine
        self._directory = directory

    @property
    def directory(self):
        if self._directory is None:
            self._directory = self.engine.directory
        return self._directory

    # ------------------------------------------------------------------ mode / kill-switch
    def mode(self):
        return self.engine.state('response_mode') or DEFAULT_MODE

    def set_mode(self, mode, actor='analyst'):
        if mode not in MODES:
            raise ValueError(f'mode must be one of {MODES}')
        self.engine.set_state('response_mode', mode)
        self._audit('mode_change', None, actor, f'response mode set to {mode}')
        return mode

    # ------------------------------------------------------------------ device lookup
    def _source_ip(self, employee_id):
        """The IP to block: the device the risk-raising event came from (the same address
        the dashboard shows), else the employee's first directory device."""
        try:
            from .views import risk_source_ip
            ip = risk_source_ip(self.engine, self.engine.brain, employee_id)
        except (OSError, ValueError, RuntimeError):
            ip = None
        owners = {d['source_ip'] for d in self.directory.data.get('devices', []) if d.get('employee_id') == employee_id}
        if ip and ip in owners:
            return ip
        return next((d['source_ip'] for d in self.directory.data.get('devices', []) if d.get('employee_id') == employee_id), None)

    # ------------------------------------------------------------------ candidates
    def candidates(self, brain):
        """Employees whose peak risk has crossed HIGH and still need a response.

        An employee with an active response is skipped. An employee whose only responses
        were reverted is skipped too, unless their peak has since risen above the highest
        peak already handled — so a manual revert sticks (the analyst's decision is not
        immediately undone), while a genuinely escalating threat re-triggers.
        """
        high = brain.employee_boundaries_['high']
        active = {r['employee_id'] for r in self.active_responses()}
        handled = {}
        for r in self.all_responses():
            if r['peak_risk'] is not None:
                handled[r['employee_id']] = max(handled.get(r['employee_id'], float('-inf')), r['peak_risk'])
        rows = self.engine.db.execute(
            'SELECT employee_id, peak_risk, peak_ts, level FROM employee_risk WHERE peak_risk >= ? ORDER BY peak_risk DESC',
            (high,)).fetchall()
        out = []
        for row in rows:
            emp = row['employee_id']
            if emp in active:
                continue
            if emp in handled and row['peak_risk'] <= handled[emp] + 1e-9:
                continue
            out.append(dict(employee_id=emp, source_ip=self._source_ip(emp),
                            peak_risk=row['peak_risk'], peak_ts=row['peak_ts'], level='high'))
        return out

    def reason_for(self, brain, employee_id, peak_risk):
        """One-line reason: the score crossing plus the strongest deviation behind it."""
        high = brain.employee_boundaries_['high']
        base = f'Peak risk {peak_risk:.3f} ≥ high boundary {high:.3f}'
        try:
            from .views import employee_events
            from .explain import event_reasons
            events = [e for e in employee_events(self.engine, employee_id) if e.get('score') is not None]
            if events:
                top_event = max(events, key=lambda e: e['score'])
                reasons = event_reasons(brain, self.directory, employee_id, top_event, top=1)
                if reasons:
                    return f'{base}; top factor: {reasons[0]["text"]}'
        except Exception:
            pass
        return base

    # ------------------------------------------------------------------ enforcement file
    def _enforcement(self):
        path = self.engine.enforcement_path
        if path and path.is_file():
            try:
                data = json.loads(path.read_text())
                data.setdefault('blocked_ips', {})
                data.setdefault('ended_sessions', {})
                return data
            except (OSError, ValueError):
                pass
        return {'blocked_ips': {}, 'ended_sessions': {}}

    def _write_enforcement(self, data):
        path = self.engine.enforcement_path
        if not path:
            return
        data['updated'] = now()
        atomic_json(path, data)

    # ------------------------------------------------------------------ apply / revert
    def respond(self, employee_id, actions=ACTIONS, created_by='auto', brain=None, peak_risk=None, reason=None):
        source_ip = self._source_ip(employee_id)
        actions = [a for a in actions if a in ACTIONS]
        if not actions:
            raise ValueError('No valid actions')
        if peak_risk is None:
            row = self.engine.db.execute('SELECT peak_risk FROM employee_risk WHERE employee_id=?', (employee_id,)).fetchone()
            peak_risk = row['peak_risk'] if row else None
        if reason is None and brain is not None and peak_risk is not None:
            reason = self.reason_for(brain, employee_id, peak_risk)
        response_id = uuid.uuid4().hex[:16]
        self.engine.db.execute(
            'INSERT INTO responses(id, employee_id, source_ip, actions, reason, peak_risk, level, created_ts, '
            'created_by, status, model_version) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
            (response_id, employee_id, source_ip, json.dumps(actions), reason, peak_risk, 'high', now(),
             created_by, 'active', self.engine.model_version))
        enforcement = self._enforcement()
        if 'block_ip' in actions and source_ip:
            enforcement['blocked_ips'][source_ip] = dict(employee_id=employee_id, since=now(), response_id=response_id)
        if 'end_session' in actions:
            enforcement['ended_sessions'][employee_id] = dict(since=now(), response_id=response_id)
        self._write_enforcement(enforcement)
        self._audit('respond', employee_id, created_by,
                    f'actions={",".join(actions)} ip={source_ip} peak={peak_risk:.3f} :: {reason}' if peak_risk is not None
                    else f'actions={",".join(actions)} ip={source_ip}')
        self.engine.db.commit()
        return response_id

    def revert(self, response_id, actor='analyst'):
        row = self.engine.db.execute('SELECT * FROM responses WHERE id=?', (response_id,)).fetchone()
        if not row or row['status'] != 'active':
            return False
        self.engine.db.execute('UPDATE responses SET status=?, reverted_ts=?, reverted_by=? WHERE id=?',
                               ('reverted', now(), actor, response_id))
        # Only lift enforcement that no other active response still requires.
        still_active = [dict(r) for r in self.active_responses() if r['id'] != response_id]
        blocked_ips = {r['source_ip'] for r in still_active if 'block_ip' in json.loads(r['actions']) and r['source_ip']}
        ended = {r['employee_id'] for r in still_active if 'end_session' in json.loads(r['actions'])}
        enforcement = self._enforcement()
        if row['source_ip'] and row['source_ip'] not in blocked_ips:
            enforcement['blocked_ips'].pop(row['source_ip'], None)
        if row['employee_id'] not in ended:
            enforcement['ended_sessions'].pop(row['employee_id'], None)
        self._write_enforcement(enforcement)
        self._audit('revert', row['employee_id'], actor, f'reverted response {response_id} (actions {row["actions"]})')
        self.engine.db.commit()
        return True

    # ------------------------------------------------------------------ auto loop
    def evaluate(self, brain):
        """In auto mode, respond to every new HIGH-peak employee. Returns created ids."""
        if self.mode() != 'auto':
            return []
        created = []
        for candidate in self.candidates(brain):
            created.append(self.respond(candidate['employee_id'], created_by='auto', brain=brain,
                                        peak_risk=candidate['peak_risk']))
        return created

    # ------------------------------------------------------------------ reads
    def active_responses(self):
        return [dict(r) for r in self.engine.db.execute("SELECT * FROM responses WHERE status='active' ORDER BY created_ts DESC")]

    def all_responses(self, limit=200):
        return [dict(r) for r in self.engine.db.execute('SELECT * FROM responses ORDER BY created_ts DESC LIMIT ?', (limit,))]

    def audit_log(self, limit=200):
        return [dict(r) for r in self.engine.db.execute('SELECT * FROM response_audit ORDER BY id DESC LIMIT ?', (limit,))]

    def _audit(self, action, employee_id, actor, detail):
        self.engine.db.execute('INSERT INTO response_audit(ts, action, employee_id, actor, detail) VALUES (?,?,?,?,?)',
                               (now(), action, employee_id, actor, detail))
