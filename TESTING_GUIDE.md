# Testing guide

## Automated suite

```bash
.venv/bin/python -m pytest -q
```

| Area | What it checks |
| --- | --- |
| Brain (`tests/test_brain.py`) | Leakage guard; normal-only fitting; data-derived levels; count-free rolling risk; dataset feature conventions; no supervised estimators. |
| Engine and collection (`tests/test_monitor.py`) | Every event scored; previous-hour counting; attribution; deduplication; rotation; malformed input; retired rule keys discarded; no rule engine left; demo dashboard ranking and explanation. |
| Collector lifecycle (`tests/test_autonomous.py`) | Journal cursors and recovery; worker restart; capacity; concurrent read-only dashboard; deployment preparation. |
| Lab (`tests/test_lab_delivery.py`) | Provisioning, including retirement of the old external-attack sources; telemetry inbox → collector → score → dashboard; unit rendering. |

Deployment and lab tests refuse to run as root, and the systemd parser test needs a user manager. Run the suite as
the normal Kali user.

## Demonstration (no live data needed)

1. In the dashboard, choose **Demonstration** and click **Run demonstration replay**.
2. This replays 48 hours of unlabelled, synthetic organisation activity (`samples/behavioral_demo.jsonl`), shifted by whole weeks so weekdays and local times are preserved.
3. The employee ranking and the AI analysis panel fill in.

## Replaying the dataset through the live collector

This needs the dataset workbook in `data/`.

1. Export an unlabelled window as raw telemetry:

   ```bash
   .venv/bin/python -m monitor.brain.replay --out runtime/replay.jsonl --since 2026-11-04T11:10:57Z
   ```

2. Add that file as a `jsonl` source (or append it to `runtime/lab/telemetry.jsonl`). The collector scores it exactly as live telemetry.

## Lab telemetry inbox

Append one JSON object per line to `runtime/lab/telemetry.jsonl` (schema in README). The collector attributes each
event via its `source_ip`, using the device addresses in `models/ai_engine/directory.json`. It scores the event and
updates that employee's rolling risk within one poll.

Phase 3 adds the six insider-scenario scripts that write to this inbox; nothing generates scenario traffic automatically.
