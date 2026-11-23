"""Insider-attack scenarios: schema validity, attribution and the projected gradient.

These tests use the committed brain and directory. They assert that each scenario
emits schema-valid telemetry attributed to the impersonated employee's device, and
that the frozen model places the loud scenarios at HIGH and the stealthy ones at
MEDIUM for the documented demonstration employees.
"""
import json
import tempfile
import types
import unittest
from pathlib import Path

from monitor.attacks import base
from monitor.attacks import (credential_misuse, data_exfiltration, data_snooping,
                             privilege_escalation, sabotage_log_tampering, sql_injection)
from monitor.brain.runtime import DEFAULT_MODEL
from monitor.brain.telemetry import normalize_event, resolve_context

MODEL_PRESENT = DEFAULT_MODEL.is_file()
SERVICES = {'Active Directory', 'DNS', 'File Server', 'Internal Web', 'Database', 'SIEM', 'SSH Gateway', 'ERP'}

# (module, demonstration employee, acceptable projected employee levels)
CASES = [
    (data_exfiltration, 'EMP0318', {'high'}),
    (sql_injection, 'EMP0026', {'high'}),
    (privilege_escalation, 'EMP0003', {'high'}),
    (sabotage_log_tampering, 'EMP0027', {'high'}),
    (data_snooping, 'EMP0009', {'medium', 'high'}),
    (credential_misuse, 'EMP0101', {'medium', 'high'}),
]


def args(employee):
    return types.SimpleNamespace(employee=employee, count=1, interval=120)


class AttackScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = base.load_directory()

    def _build(self, module, employee):
        source_ip = base.device_ip(self.directory, employee)
        person = base.employee(self.directory, employee)
        return source_ip, module.build(self.directory, source_ip, person, args(employee))

    def test_records_are_schema_valid_and_attributed(self):
        for module, employee, _ in CASES:
            source_ip, records = self._build(module, employee)
            self.assertTrue(records)
            for record in records:
                self.assertEqual(record['source_ip'], source_ip)
                self.assertIn(record['destination_service'], SERVICES)
                # The collector must accept and attribute every emitted record.
                prepared = resolve_context(normalize_event(record), self.directory)
                self.assertEqual(prepared['employee_id'], employee,
                                 f'{module.__name__} must impersonate {employee}')

    def test_impostor_employee_is_rejected(self):
        with self.assertRaises(SystemExit):
            base.device_ip(self.directory, 'EMP9999')

    def test_count_is_capped(self):
        stamps = base.spaced(1_000_000.0, count=10_000, interval=60)
        self.assertEqual(len(stamps), base.MAX_EVENTS)

    @unittest.skipUnless(MODEL_PRESENT, 'committed brain required')
    def test_projected_gradient_matches_design(self):
        for module, employee, acceptable in CASES:
            _, records = self._build(module, employee)
            projection = base.project_levels(records)
            self.assertIsNotNone(projection, 'brain projection should be available')
            self.assertIn(projection['projected_employee_level'], acceptable,
                          f'{module.__name__} ({employee}) projected '
                          f"{projection['projected_employee_level']}, expected one of {acceptable}")

    @unittest.skipUnless(MODEL_PRESENT, 'committed brain required')
    def test_projected_gradient_is_the_same_on_any_day(self):
        """Day of week is a model feature: the scenarios must not drift with the run date."""
        from datetime import datetime
        from unittest.mock import patch
        from zoneinfo import ZoneInfo
        zone = ZoneInfo(self.directory.timezone)
        for day in range(14):                       # two full weeks, every weekday incl. weekends
            for hour in (0, 12, 23):
                run_at = datetime(2026, 11, 9 + day, hour, 3, tzinfo=zone).timestamp()
                with patch.object(base, 'now_ts', return_value=run_at):
                    for module, employee, acceptable in CASES:
                        _, records = self._build(module, employee)
                        self.assertTrue(all(r['ts'] < run_at for r in records))
                        self.assertTrue(all(run_at - r['ts'] <= 7 * 86400 for r in records))
                        level = base.project_levels(records)['projected_employee_level']
                        self.assertIn(level, acceptable, f'{module.__name__} run on {datetime.fromtimestamp(run_at, zone)}')

    def test_credential_misuse_hour_is_opposite_the_employees_habit(self):
        from datetime import datetime
        from monitor.brain.runtime import load_brain
        habit = load_brain().baseline_.hour('EMP0101')
        usual = (habit[0] % (2 * 3.141592653589793)) * 24 / (2 * 3.141592653589793)
        hour = base.opposite_habit_hour(base.employee(self.directory, 'EMP0101'))
        self.assertGreaterEqual(min(abs(hour - usual) % 24, 24 - abs(hour - usual) % 24), 11.5)
        _, records = self._build(credential_misuse, 'EMP0101')
        local = datetime.fromtimestamp(records[0]['ts'], __import__('zoneinfo').ZoneInfo(self.directory.timezone))
        self.assertEqual(local.hour, hour)
        self.assertNotIn(local.weekday(), self.directory.weekend_days)

    def test_emit_appends_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            inbox = Path(tmp) / 'telemetry.jsonl'
            _, records = self._build(data_exfiltration, 'EMP0318')
            base.emit(records, inbox)
            base.emit(records, inbox)
            lines = inbox.read_text().splitlines()
            self.assertEqual(len(lines), 2 * len(records))
            self.assertEqual(json.loads(lines[0])['destination_service'], 'File Server')

    def test_sabotage_action_modifies_watched_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            watched = Path(tmp) / 'settings.txt'
            watched.write_text('mode=baseline\n')
            before = watched.read_text()
            # Point the action at our temporary watched file via a patched locator.
            original = sabotage_log_tampering._watched_file
            sabotage_log_tampering._watched_file = lambda: watched
            try:
                message = sabotage_log_tampering.action(types.SimpleNamespace())
            finally:
                sabotage_log_tampering._watched_file = original
            self.assertIn('tamper', message.lower())
            self.assertNotEqual(watched.read_text(), before)

    def test_sql_message_states_rows_returned_truthfully(self):
        from monitor.lab import Catalog, CATALOG_ROWS
        catalog = Catalog()
        try:
            results = catalog.search(sql_injection.INJECTION)        # the lab's real query
        finally:
            catalog.close()
        self.assertEqual(set(results), set(CATALOG_ROWS))            # the payload really dumps the catalog
        note = sql_injection.describe(results)
        self.assertIn("returned 2 of 2 catalog rows: 'pencil', 'notebook'.", note)
        self.assertIn('widened the query to every row', note)
        partial = sql_injection.describe(['pencil'])
        self.assertIn("returned 1 of 2 catalog rows: 'pencil'.", partial)
        self.assertIn('not dumped', partial)
        self.assertNotIn('every row', partial)
        self.assertIn('returned 0 of 2 catalog rows: none.', sql_injection.describe([]))

    def test_sql_action_handles_unreachable_target(self):
        # No lab web server in the test environment: the action must degrade, not raise.
        note = sql_injection.action(types.SimpleNamespace())
        self.assertIsInstance(note, str)
        self.assertTrue(note)


if __name__ == '__main__':
    unittest.main()
