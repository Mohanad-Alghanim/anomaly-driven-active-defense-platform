# Autonomous upgrade validation — 7 November 2026

## Automated results

Environment: Kali Linux workspace, Python 3.14, Streamlit 1.66.1, existing project-local `.venv`. No new Python dependencies were needed for this upgrade.

- `.venv/bin/python -m unittest discover -s tests -v`: **36 tests passed**.
- `.venv/bin/python -m pip check`: **No broken requirements found**.
- `bash -n start.sh`: passed.
- `desktop-file-validate` on the four generated user launchers: passed.
- `git diff --check`: passed.

The tests cover:

- All six existing detection rules, inclusive SSH boundary, request threshold configuration, normal handling, distinct-port counting and source-IP isolation.
- Normal sudo/su sessions, Journal parsing, bounded oldest-first Journal batches, durable cursor reuse, expired-cursor fallback with replay deduplication, and permission-error reporting. The integration Journal reader is injected synthetic output, not a modified system Journal.
- Real incremental file ingestion, partial lines, log rotation, invalid/oversized records, missing sources and non-regular files without blocking.
- File content changes and authorized hashes in temporary test files.
- A full mixed-source synthetic path: Journal authentication records, raw common/combined HTTP logs, raw firewall records, a temporary file modification, the background collection cycle, all six rules, SQLite persistence and the dashboard read model. Exactly one alert per category was produced; a restarted engine replayed without duplicate events or alerts.
- A real standalone worker process (no Streamlit browser), graceful termination, restart, newly appended event collection, persisted progress and private database permissions.
- Existing database schema migration without losing old records, concurrent writer/read-only dashboard access, single-collector locking, byte/event capacity reporting and stale heartbeat detection.
- Streamlit AppTest startup, six-category demo, repeated demo replacement, category filtering, live worker-health rendering and source/destination fields. The live view is tested to avoid invoking collection.
- Preparation of user services and launchers without activating anything; graphical activation cancellation prevents service activation.

Default demonstration remains **74 events, 68 NORMAL, 6 ABNORMAL, 6 alerts**. All samples and integration fixtures are synthetic. Tests used temporary SQLite databases and temporary lab files. No real cyberattack was executed.

## Confirmed environment probes

- Read-only `journalctl` worked without sudo.
- An existing sudo Journal record was retrieved and parsed as a privilege event. Its raw content was not saved in repository artifacts or printed in tool output. This establishes access/format compatibility for that record, not real attack detection accuracy.
- A standalone one-cycle collector using the actual authentication Journal query reported RUNNING with a readable source and no recent matching records. It used an ignored validation data directory, not production data.
- The project's existing local log configuration content was preserved.
- The user service templates and four graphical launchers were installed in Kali's user configuration/applications/Desktop locations. Preparation did not enable or start the services. The installer protected only this application's data and configuration.

## Deployment restrictions and outstanding checks

The development sandbox rejects access to the systemd user bus (`Operation not permitted`). Both `systemctl --user` inspection and systemd's user-service verification encountered this restriction. Service activation, service-manager restart policy, actual after-login startup and logout/login behavior are **not confirmed** here.

The updated dashboard launcher was invoked and reached Streamlit server startup, but socket creation failed with `PermissionError: [Errno 1] Operation not permitted`. A listening HTTP endpoint, actual Firefox visuals, graphical dialogs, and timed browser refresh are **not confirmed** in this environment. Streamlit's in-process AppTest executed successfully without sockets.

Because user services could not be activated here, deployment is **prepared, not confirmed active**. On the ordinary Kali desktop, open **Activate SOC Monitoring** once and approve its local-service confirmation. Then open **Six-Attack SOC**, check collector/source health, close Firefox briefly, and reopen it to confirm collection continued. Log out/in to verify automatic startup. Use **SOC Monitoring Status** or the documented user-service commands if activation fails.

## Real telemetry remains operator setup

No SSH service was enabled, firewall rule changed, packet capture activated, system security setting changed, extra web target introduced or remote endpoint exposed. Actual HTTP/firewall/lab-file inputs must be selected in `config.local.json` and provided by the isolated target's existing approved logging mechanisms. The environment's installed-but-inactive SSH service was left untouched.

Real SSH brute force, port scanning, SQL injection, DoS, unauthorized lab-file activity and privilege-escalation tests have not been performed. Synthetic end-to-end validation is not real-world attack validation. Initial dependency installation on a fresh Kali machine also remains unverified; the project-local Python environment was already installed during the original implementation.
