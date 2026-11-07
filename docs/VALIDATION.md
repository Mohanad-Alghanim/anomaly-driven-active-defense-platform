# Local validation — 7 November 2026

## Environment and results

- Kali Linux workspace, Python 3.14, Streamlit 1.66.1.
- `./.venv/bin/python -m unittest discover -s tests -v`: **17 tests passed**.
- `./.venv/bin/python -m pip check`: **No broken requirements found**.
- `bash -n start.sh`: passed.
- Six-category demonstration: **74 events, 68 NORMAL, 6 ABNORMAL, 6 alerts** with default thresholds.
- Repeating the dashboard demonstration replaces the previous demo dataset and produces the same counts.
- JSONL ingestion of the complete scenario produced all six categories; rereading did not duplicate stored events or alerts.
- Streamlit AppTest rendered the dashboard, demo controls, metrics, SQL category filtering, and empty live mode without application exceptions.
- Database persistence, IP/window boundaries, alert fields, source rotation, partial lines, missing sources, file content changes, authorized hashes and duplicate suppression passed automated tests.

A dedicated `.venv` was created in this project. Because shell networking is restricted, installed Streamlit/Pandas dependency files were copied into it from an existing local environment. The copied environment has no runtime dependency on that other checkout, and its dependency metadata passes pip check. A fresh internet installation was not verified here. The environment is ignored by Git and is not distributed in the repository.

## Runtime limitation

Running `./start.sh --server.port 8514 --server.headless true` reached Streamlit's server startup, but the execution sandbox rejected socket creation with `PermissionError: [Errno 1] Operation not permitted`. The same restriction prevented a localhost HTTP health probe. Consequently, a listening HTTP server, actual browser visuals, and timed browser refresh were **not verified** in this environment. AppTest successfully executed and checked the application without sockets.

Run `./start.sh` in an ordinary Kali terminal, visit http://localhost:8501, click the demonstration button, and check the counts above. Keep the page open to allow automatic refresh. This runtime check remains outstanding; no live server launch success is claimed.

## Scope of evidence

All security events used for validation were synthetic. File-monitor tests changed only temporary test files. No cyberattacks were executed. Actual SSH/firewall/web traffic, privileged operating-system logs, fresh Kali installation, and real-world detection accuracy were not validated. The collector requires appropriate readable telemetry and an active dashboard session; see README for source and polling limitations.
