# Six-Attack SOC Monitoring System

A lightweight, local SOC dashboard for Kali Linux using Python, Streamlit and SQLite. A background collector monitors configured telemetry independently of Firefox. Exactly six transparent rule categories identify possible suspicious activity; a match is an indicator to investigate, not proof of an attack.

No Codex, cloud API, AI, paid service, Docker or external monitoring platform is required during operation.

## Install once, then use the desktop

Python 3.10+ and a normal Kali desktop user are required. Locally tested with Python 3.14 / Streamlit 1.66.1.

```bash
git clone https://github.com/Mohanad-Alghanim/six-attack-security-monitor.git
cd six-attack-security-monitor
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m monitor.install --prepare
```

For an existing checkout, update the code and dependencies, then run only the preparation command. Existing `config.local.json` content and recorded databases are preserved. Preparation adds user services and application/desktop launchers. It does **not** enable or start a listener. No sudo, system service, SSH enablement, firewall change, packet capture or linger setting is used.

1. Open **Activate SOC Monitoring** from the applications menu (or desktop). It asks before enabling login startup and starting the collector and localhost dashboard.
2. Open **Six-Attack SOC** to launch Firefox at **http://127.0.0.1:8501**.
3. Keep using Kali normally. Closing Firefox or a terminal does not stop collection.
4. On subsequent user logins, systemd starts both services automatically. Open Six-Attack SOC whenever needed.

The graphical confirmation uses Zenity when available, otherwise Python's tkinter. If your desktop marks a new desktop file untrusted, use its normal **Allow Launching** / executable launcher action, or launch it from the applications menu. A minimal Kali install may need its normal `python3-venv` and `python3-tk` packages installed by its administrator. Initial package installation requires internet or locally supplied wheels; normal operation is offline.

**Current delivery environment:** service files and launchers were prepared, but activation and an actual browser server could not be verified because the development sandbox blocks the systemd user bus and network sockets. One-time graphical activation remains necessary on the real Kali desktop. See [validation evidence](docs/VALIDATION.md).

## Day-to-day workflow

Start Kali, log in, open Six-Attack SOC, and use your separate terminal to perform authorised testing against your designated isolated lab target. The target's **existing, readable telemetry** must record that activity. The collector reads new records, the six rules evaluate them, and the dashboard refreshes every three seconds. Events and alerts persist across supported collector/service restarts.

Authentication Journal access alone does not provide firewall or HTTP telemetry. SSH is not enabled by this application. If SSH is inactive or a target does not export suitable logs, the corresponding activity cannot be detected. Source health and per-category requirements are shown explicitly. A readable source is not proof of complete event coverage.

## Six categories and telemetry

| Category | Default indicator | Supported source |
| --- | --- | --- |
| SSH Brute Force | 5 failed SSH logins from one IP in 60 seconds | Persistent local authentication Journal or `auth` / normalized records |
| Port Scanning | 15 distinct destination ports from one IP in 60 seconds | Existing netfilter/UFW logs or normalized connection records |
| SQL Injection | Predefined suspicious SQL request patterns | Apache/Nginx common/combined access logs or normalized HTTP records |
| Denial of Service (DoS) | 50 HTTP requests from one IP in 10 seconds | Same HTTP request sources |
| Unauthorized File Modification | Content changed without matching approved hash | Explicitly selected readable lab files |
| Suspicious Privilege Escalation | Predefined suspicious sudo/su/authentication/command patterns | Local authentication Journal or `auth` / normalized privilege records |

No other attack categories are implemented. Normal sudo/su sessions and routine privileged commands do not automatically trigger alerts. The selected patterns include sudoers denial, privilege authentication failure, and particular shell/setuid/admin-group commands. Some legitimate administrative commands can match; investigate the context.

## Configure your actual lab sources

Edit ignored `config.local.json` in a text editor. The default enables read-only local authentication Journal queries and leaves other telemetry unconfigured. [config.lab.example.json](config.lab.example.json) illustrates available source adapters; its paths are placeholders, not ready-to-use sources.

```json
{
  "journal": {"enabled": true, "lookback_seconds": 300, "kernel_netfilter": false},
  "sources": [
    {"path": "/path/to/existing/lab-access.log", "format": "http_access", "destination": "isolated-lab", "destination_port": 8080},
    {"path": "/path/to/existing/lab-firewall.log", "format": "netfilter"},
    {"path": "/path/to/existing/normalized.jsonl", "format": "jsonl", "kinds": ["ssh_failed", "connection", "http", "privilege"]}
  ],
  "files": [{"path": "/path/to/explicitly-selected/lab-file.txt"}]
}
```

Use absolute paths for deployment. Configuration is reloaded by the collector each cycle; refresh the browser after editing it so its displayed coverage settings update too. Existing configurations without a `journal` key inherit the new default enabled Journal query. `kinds` declares intended JSONL coverage for the status table; it does not synthesize records or enable a detector source. An undeclared JSONL source is still read, but is not claimed as category coverage.

The Kali user must already have permission to read these sources. We do not change system log permissions or group membership. For a different lab machine, local Journal records describe **Kali**, not that remote target. Make the target's logs available through an already approved readable shared file or existing log forwarding facility. This application adds no remote listener or automatic remote administration. See [lab telemetry setup](docs/LAB_TELEMETRY.md).

## Dashboard and demonstration

The default view is **Live monitoring**. It shows collector heartbeat/state, source availability, last processed event/time, event counts, attack distribution, timeline, recent alerts with severity, source/destination details, event details, and category/time filters. Alert records link event time and detection time to the rule, explanation and recommended action. Read-only queries fetch at most 1,000 recent details; totals and charts cover the full selected time range.

Choose **Demonstration** and click its button to replace the isolated demo dataset with a fresh scenario. At default thresholds: **74 events, 68 NORMAL, 6 ABNORMAL, 6 alerts**. This simulates records only; it does not run attacks. Demo and live databases are always separate. Saved examples are in `samples/`; adapter fixtures in `samples/lab/` are synthetic, including their Journal cursor strings. Automated integration tests use temporary databases, not the real live database.

## Reliability and storage

- One collector per data directory, enforced with a process lock. It persists Journal cursors, log byte offsets, file hashes and health in SQLite.
- Cursor commits follow event commits, so an interruption replays safely. Duplicate event IDs and alert cooldowns prevent duplicate ingestion/alerts.
- Expired Journal cursors recover from the last saved timestamp with a two-second overlap. First startup reads the previous five minutes by default. Logs already vacuumed away cannot be recovered.
- Log reads are bounded (1,000 lines/source/poll by default); partial lines wait for their newline, oversized records are skipped and reported. Inode rotation/detected truncation restarts reading. Same-inode replacement and copy/truncate races are not lossless; retain source logs as needed.
- SQLite WAL and a busy timeout support concurrent collector writes and dashboard reads. Existing project databases migrate additively. All matched events now retain category details even when a repeat alert is suppressed; older suppressed events keep their original stored status without retroactive rule evaluation.
- Default capacity: 200,000 events / approximately 256 MiB database plus WAL, with bounded batch/check overshoot. At capacity, ingestion pauses visibly; history is not silently deleted. Archive and configure a new data directory or explicitly adjust the limits. Free space and source-log retention remain the operator's responsibility.
- New data is private to the user (directory 0700, files 0600 via umask). Preparation tightens permissions only on this application's own data/config, never system log permissions. No event payloads are printed to service logs.
- User services have restart backoff, CPU/memory limits and a private umask. Collection continues while the user is logged in. Logout/shutdown normally stops user services; they resume at next login. Linger is not enabled.

Threshold windows use event timestamps and inclusive boundaries. Earlier contributors keep NORMAL until a rule actually triggers. Late events do not retroactively reclassify older records. NORMAL means no configured rule matched. SQL patterns are intentionally limited; access-log requests are URL-decoded once. The normalizer does not interpret arbitrary custom log layouts, proxy trust chains or HTTP request bodies. File hashing detects content, not permissions/metadata; changes and reversions between polls may be missed. These are educational rules, not a comprehensive intrusion detection platform.

## Status, recovery and stopping

Use **SOC Monitoring Status** for graphical service state; use **Restart SOC Monitoring** for graphical recovery. The restart asks before starting/restarting the localhost service and preserves database progress. Service logs are accessible through the normal desktop journal viewer, if installed.

Optional terminal administration (not needed for routine operation):

```bash
# One-time activation without the GUI
.venv/bin/python -m monitor.install --activate

systemctl --user status six-soc-collector.service six-soc-dashboard.service
systemctl --user restart six-soc-collector.service six-soc-dashboard.service
journalctl --user -u six-soc-collector.service -u six-soc-dashboard.service -n 50 --no-pager

# Stop now; enabled services resume at next login
systemctl --user stop six-soc-dashboard.service six-soc-collector.service

# Disable login startup and stop both
systemctl --user disable --now six-soc-dashboard.service six-soc-collector.service
```

For an upgrade, restart both services after preparation. If repeated failures exhaust systemd's start limit, run `systemctl --user reset-failed six-soc-collector.service six-soc-dashboard.service` then restart. The dashboard's stale heartbeat warning helps distinguish an inactive collector from quiet traffic. A bind failure may mean port 8501 is occupied: inspect service logs and resolve the conflict yourself rather than terminating unrelated processes.

Manual development fallback: run `.venv/bin/python -m monitor.worker` independently, then `./start.sh` for the dashboard. Stop each with Ctrl+C. `SIX_CONFIG` and `SIX_DATA` override paths for these commands; generated services use explicit project-local paths. Do not run the dashboard as root.

## Tests and project layout

```bash
.venv/bin/python -m unittest discover -s tests -v
```

See [validation evidence](docs/VALIDATION.md) for actual results and unverified items. The suite exercises six rules, normalization, durable cursors, expired-cursor recovery, log ingestion, database migration/persistence, process restarts without a browser, duplicate suppression, source health, concurrency, resource limits, dashboard rendering, and the synthetic six-category telemetry-to-alert path. It does not execute real attacks.

```text
app.py                     Read-only live dashboard, separate demo controls
monitor/core.py            Existing six rules, storage and additive migration
monitor/adapters.py        Auth, Journal, HTTP and firewall normalization
monitor/collectors.py      Incremental file readers and integrity checks
monitor/journal.py         Bounded Journal queries and durable cursor recovery
monitor/worker.py          Independent collector lifecycle and health
monitor/views.py           Bounded dashboard queries and source coverage
monitor/install.py         User-service and graphical launcher installation
deploy/                    systemd user-service templates
samples/                   Synthetic saved telemetry and adapter fixtures
tests/                     Automated rule, lifecycle and integration tests
```
