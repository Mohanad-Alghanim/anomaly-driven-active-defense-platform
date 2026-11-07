# Six-Attack Security Monitoring System

A lightweight local SOC dashboard for Kali Linux, built with Python, Streamlit and SQLite. Exactly six rule categories produce indicators of possible attacks. Rule matches require investigation; they are not proof of malicious activity. No Codex, cloud service, AI, containers or paid API is needed to operate it.

## Install and start

Python 3.10 or newer is required (locally tested with Python 3.14).

```bash
git clone https://github.com/Mohanad-Alghanim/six-attack-security-monitor.git
cd six-attack-security-monitor
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp config.example.json config.local.json
chmod +x start.sh
./start.sh
```

Open http://localhost:8501. Stop with **Ctrl+C**. If venv support is missing, install Kali's `python3-venv` package through your usual package management process. Initial dependency installation requires internet or locally supplied wheels; operation after installation is offline. The server binds to localhost.

## Demonstration

Select **Demonstration** and click **Run six-category demonstration**. Each run replaces the previous demo dataset with 74 simulated events, 68 NORMAL and 6 ABNORMAL, producing one alert per category under default thresholds. Earlier events contributing to a threshold remain NORMAL until a rule actually triggers. The button never executes an attack or makes a network request.

Demo and live data use separate SQLite databases under ignored `data/`. Documentation-only IP addresses are used. `samples/demo.jsonl` supplies a saved, deterministic dataset; its timestamps are fixed. Use the built-in button for fresh timestamps. Sample timestamps can be rebased when replaying them into a current time view. Identical imported events are idempotent.

## Sources and configuration

`config.local.json` is ignored by Git. Set `SIX_CONFIG` to select another configuration file and `SIX_DATA` to choose a database directory. Configuration is loaded on a full dashboard rerun.

```json
{
  "ssh_count": 5, "ssh_window": 60,
  "port_count": 15, "port_window": 60,
  "dos_count": 50, "dos_window": 10,
  "sources": [
    {"path": "/path/to/readable/auth.log", "format": "auth"},
    {"path": "/path/to/normalized-traffic.jsonl", "format": "jsonl"}
  ],
  "files": [{"path": "/path/to/test-file.txt"}]
}
```

| Category | Required telemetry | Default rule |
| --- | --- | --- |
| SSH Brute Force | Readable OpenSSH authentication log or normalized `ssh_failed` records | 5 failures/IP within 60 seconds |
| Port Scanning | Firewall/connection records with destination ports | 15 distinct ports/IP within 60 seconds |
| SQL Injection | HTTP request records including request text | Predefined SQL patterns |
| Denial of Service (DoS) | HTTP request records | 50 requests/IP within 10 seconds |
| Unauthorized File Modification | Explicitly configured test files | Content hash changes without approved hash |
| Suspicious Privilege Escalation | sudo/su authentication or normalized privilege records | Predefined suspicious privilege patterns |

The auth adapter handles traditional syslog `Failed password` and sudo/su records. Journald-only installations must export logs to readable files or normalize records externally. Traditional syslog lacks a year; the adapter infers the current local year. It does not support every SSH failure or authentication log format. No permissions or system security settings are changed.

HTTP and firewall telemetry must be supplied as normalized JSONL. This application does not sniff packets or automatically parse arbitrary web server logs. The dashboard shows configured source read status and a category/source requirements table. A configured JSONL file does not guarantee it contains every required event kind.

Each JSONL line needs numeric Unix `ts` (UTC seconds), `kind`, and string `message`. Optional fields are `ip`, `port`, `authorized`, and `id`. Supported kinds: `normal`, `ssh_failed`, `connection`, `http`, `file`, `privilege`. A connection event requires a valid destination port. Example:

```json
{"ts":1794042000,"kind":"connection","ip":"192.0.2.10","port":443,"message":"Firewall connection attempt"}
```

Only supply `authorized: true` on normalized file events from a trusted producer. For built-in file monitoring, compute the intended new file's SHA-256 and place it in the entry's `authorized_sha256` field **before** applying the change. The first observation establishes the baseline. Unauthorized content changes trigger alerts; metadata-only changes do not. Changes and reversions between polls can be missed. File deletion/read failures appear as source errors. Use test files rather than sensitive system files.

## Processing behavior

Append newline-terminated records in timestamp order. Durable byte offsets prevent rereading on refresh. Inode rotation and detected truncation restart reading. At most 5,000 lines per source are read per refresh. Invalid lines are skipped; a per-poll rejection count is shown. The collector cannot detect every in-place rewrite or copy/truncate race, and does not read the remainder of renamed rotated logs. Keep rotated logs externally if needed.

NORMAL means no configured rule matched. A triggering event is ABNORMAL. Every alert includes attack name, processing/detection time, source IP if available, severity, triggered rule, description, recommendation, event time and event ID. Earlier events contributing to a threshold keep their original classification.

Threshold rules suppress duplicate alerts for the same category/IP during the corresponding rule window; repeated matching events still become ABNORMAL. Identical event IDs are not processed twice. Imported log IDs are derived from source/inode/offset/content. Multiple sources sharing an IP contribute to the same rule window. Time/category filters apply to event time; category views display alert-linked events, while All includes suppressed matching events.

SQL patterns cover UNION SELECT, quoted OR 1=1, semicolon DROP TABLE and SQL comments. Privilege patterns cover authentication failures, sudoers denial, and shell/setuid/admin-group commands. Expressions are defined in `monitor/core.py`; thresholds/windows are configurable positive integers. Encoded HTTP payloads are not decoded. Predefined patterns can produce false positives and miss attacks. Late/out-of-order events do not retroactively re-evaluate earlier events. Imported timestamps are trusted.

Collection runs every three seconds while the dashboard has an active browser session. There is no background daemon; closing the browser or stopping Streamlit stops collection. The app reads persisted data again when reopened. SQLite uses WAL, parameterized values and transactional processing. For long-running deployments, add suitable retention and a dedicated collector; this project deliberately keeps both simple. Stop the application before archiving/removing database files. Protect databases and logs with normal filesystem permissions.

## Structure and tests

```text
app.py                    Streamlit dashboard and refresh
monitor/core.py           Six rules, ingestion, normalization, SQLite
monitor/demo.py           Safe, deterministic demonstration scenarios
samples/demo.jsonl        Saved sample telemetry
config.example.json       Configurable thresholds and sources
start.sh                  Independent local startup
tests/test_monitor.py    Automated rule/integration/dashboard tests
docs/VALIDATION.md       Local validation evidence and limitations
```

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Tests cover all six rules, normal classification, boundaries, IP isolation, alert fields, persistence, deduplication, file authorization, invalid input, incremental ingestion and Streamlit startup/demo/filter rendering. No real-world attack detection is claimed. See [validation notes](docs/VALIDATION.md) for the tested environment and limits.
