# Development of an Anomaly-Driven Active Defense Platform Against Unauthorized Access and Credential Attacks

A local Kali Linux SOC platform for **insider-threat detection with unsupervised AI**. A background collector reads
telemetry and stores it in SQLite. Every event is scored by an Isolation Forest trained on **normal behaviour only**,
and the dashboard ranks **employees** by a rolling risk score. Selecting an employee shows which of their own
behaviour patterns deviated, and by how much.

There are **no detection rules and no hand-written thresholds**. Low/medium/high are quantiles (P95/P99) of the score
distribution of independent normal behaviour, fixed when the model is trained. A high score is a deviation that
requires investigation, not proof of intent.

![Employee risk ranking](docs/screenshots/phase2_home_employee_ranking.png)

## How it works

| Step | Where | What |
| --- | --- | --- |
| Collect | `monitor/collectors.py`, `journal.py`, `adapters.py`, `worker.py` | Bounded incremental reads of JSONL behavioural telemetry, HTTP access logs, netfilter logs, the systemd Journal and watched files; durable cursors; one writer. |
| Attribute | `monitor/brain/telemetry.py` | `source_ip → device → employee` via `models/ai_engine/directory.json`. Unknown sources are stored and scored but not ranked. |
| Derive | `monitor/brain/telemetry.py` | The dataset's features: local time (cyclic), weekend, scheduled hours, log bytes/latency, service/protocol, events from the same source in the previous hour. They match the training workbook to floating-point precision. |
| Score | `monitor/core.py` → `monitor/brain` | Personal deviation from the employee's own baseline, plus Isolation Forest anomaly score and data-derived level per event. |
| Aggregate | `monitor/brain/risk.py` | Employee risk = time-decayed mean of recent event scores (half-life 24 h). Event counts do not raise risk. |
| Explain | `monitor/brain/explain.py`, `app.py` | Plain-language reasons: which personal features deviated and by how many standard deviations. |

Model results, including the full model next to the artifact-free floor, are in
[docs/PHASE1_BRAIN_REPORT.md](docs/PHASE1_BRAIN_REPORT.md). The Phase 2 integration is described in
[docs/PHASE2_INTEGRATION_REPORT.md](docs/PHASE2_INTEGRATION_REPORT.md), and the overall plan in
[docs/MIGRATION_PLAN.md](docs/MIGRATION_PLAN.md).

## Install

Python 3.11+ is required.

```bash
git clone https://github.com/Mohanad-Alghanim/anomaly-driven-active-defense-platform.git
cd anomaly-driven-active-defense-platform
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m monitor.install --prepare
.venv/bin/python -m monitor.install --prepare-lab
```

Then use the graphical **Active Defense Platform — Start Monitoring** control and approve activation. The dashboard is
at **http://127.0.0.1:8501**. Do not run the dashboard or lab as root.

The trained model, the organisation directory and a demo replay are committed. Retraining needs the dataset workbook
in `data/` (Git-ignored):

```bash
.venv/bin/python -m monitor.brain.train
```

## Lab

The loopback lab provides:
* an Internal Web target at `127.0.0.1:8088`, with a real access log;
* a watched file;
* a **telemetry inbox**, `runtime/lab/telemetry.jsonl`, where the Phase 3 insider-scenario scripts will write events in the behavioural schema.

```json
{"ts": "2026-11-20T09:15:00+03:00", "source_ip": "10.200.0.10", "destination_ip": "10.10.1.20",
 "destination_port": 445, "protocol": "TCP", "bytes_in": 1500, "bytes_out": 600, "response_time_ms": 42,
 "kind": "file_read", "message": "free text"}
```

`destination_service` and `protocol` are filled from the server directory when omitted. See [TESTING_GUIDE.md](TESTING_GUIDE.md).

## Tests

```bash
.venv/bin/python -m pytest -q
```

## Operation and reliability

- **Timing.** Collection runs every two seconds and the dashboard refreshes every three. Collection is independent of the browser.
- **Persistence.** Journal cursors, file offsets, hashes and heartbeats are persisted. Events are stored and scored before a cursor moves, so a crash replays and never skips.
- **Storage.** SQLite runs in WAL mode with one collector lock and deterministic event identities. Older databases migrate additively; historical rows and old rule-era alert tables are preserved but no longer written.
- **Capacity.** The default limits (200,000 events, about 256 MiB) pause collection visibly instead of deleting history.
- **Model identity.** The collector reports the model version (a hash of the artifact) in its health. Changing the model requires restarting the collector.
