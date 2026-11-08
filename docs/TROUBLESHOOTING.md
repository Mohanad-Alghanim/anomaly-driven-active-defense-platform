# Lab troubleshooting and recovery

## Start or restart without a terminal

Use **Active Defense Platform — Start Monitoring** or **Active Defense Platform — Restart Monitoring**. Each asks before enabling/restarting the localhost services. No attack tests are scheduled. Use **Active Defense Platform — Component Health** for current service/target state, and **Anomaly-Driven Active Defense Platform** for telemetry/validation status.

If startup fails, existing history is preserved. Use **Active Defense Platform — Stop Monitoring** to stop only project processes. The host SSH service is independent and remains unchanged. Enabled user units restart at next login; disable them explicitly if that is not wanted.

## WorkingDirectory quotation regression

Older templates wrapped WorkingDirectory in quotes, producing an invalid literal path on this Kali deployment. The repository now renders `WorkingDirectory=/absolute/project/path` without surrounding quotes, while retaining appropriate ExecStart argument quoting. Percent specifiers are escaped, and regression tests include paths with spaces/percent signs. The unit renderer validates this before installation.

The existing manually repaired units were preserved by `--prepare-lab`. A future full `--prepare` generates the corrected form. Do not rewrite the currently working units merely to install lab targets.

Optional inspection:

```bash
systemctl --user cat active-defense-collector.service active-defense-dashboard.service active-defense-lab.service
```

## Sandbox or missing desktop session

`Operation not permitted` when accessing the user bus or creating a socket is a development-environment limitation. It is not proof of an attack or a reason to run the dashboard as root. Run activation on the normal Kali desktop. The application does not use sudo to bypass these restrictions. Actual Firefox and user-manager validation remain outstanding until performed there.

Tkinter or Zenity needs the desktop display. The launchers run with the project as their working directory. If the desktop initially marks a new file untrusted, use the desktop's normal Allow Launching action or the applications menu.

## Port conflict / partial startup

The fixed lab endpoints are loopback 8088, 2222 and 9100–9119; dashboard 8501. Startup fails rather than killing an unrelated process or moving to undocumented ports. Inspect Component Health and the lab service log. Resolve any unrelated conflicting application deliberately, then use Restart. The lab refuses an altered managed SSH configuration to avoid accidental remote exposure.

```bash
systemctl --user status active-defense-lab.service active-defense-collector.service active-defense-dashboard.service
journalctl --user -u active-defense-lab.service -n 50 --no-pager
```

If repeated failures hit systemd's start limit, the graphical Start/Restart control resets the failed state before restarting. It preserves SQLite and cursors.

## Native privilege test stays NORMAL

The old running collector does not automatically reload Python detector code. The new capability-denial rule needs **one restart after this upgrade**. The test wrapper checks `rules_version=3` and refuses to run against an older collector. Restart through the graphical control, then run the bounded privilege command again. Do not manually inject audit JSON, edit stored classifications or run the probe as root.

The probe validates EPERM for a real capability request. Root, pre-existing CAP_SETUID, another errno, or an unavailable native interface is UNVERIFIED. Ordinary sudo/su/getuid activity remains NORMAL unless a defined suspicious rule matches.

## No new alert on a repeated test

Use the bounded wrappers from TESTING_GUIDE.md. They wait for the preceding source/window to expire where necessary; duplicate suppression intentionally prevents repeated threshold alerts within a window. All matching events still retain ABNORMAL classification. Category filters include matched events, and historical alerts remain stored. Ensure the selected dashboard time range includes the new event and use Live monitoring rather than Demonstration.

The runner requires a **new alert from the exact lab source**. An old host SSH alert or an unrelated host privilege event cannot turn a failed test into a reported success.

## Source readable but target unverified

An empty access/auth log can be readable while the lab is stopped. The readiness panel distinguishes source availability, actual component heartbeat and pipeline evidence. Network categories remain UNVERIFIED until real activity is observed and verified; synthetic fixtures and demo clicks never change that evidence.

## File baseline / interrupted cleanup

The watched target is only `runtime/lab/watched/settings.txt`. The bounded file test restores its approved baseline even on Ctrl+C. If power loss or a hard kill prevented cleanup, use the exact restoration command in TESTING_GUIDE.md. Changing metadata alone is outside content-hash detection. Do not delete hash/cursor/database state to manufacture an alert.

## Capacity or rotation

At the configured event/database cap, ingestion pauses visibly rather than deleting history. Stop the project, archive deliberately, and choose a new private data location or adjust capacity after review. Native logs rotate at 8 MiB with three retained generations. Very fast rotation can outrun the simple file reader; normal bounded tests are far smaller. Raw rotated data may contain local telemetry and must never be committed.

## Missing host binaries on another installation

This Kali environment already has sshd, ssh-keygen, ssh, sshpass, curl/nmap and `/run/sshd`; SSH config validation passed. A fresh/minimal machine may differ. Missing system packages or creation of privileged host directories require explicit administrator approval. No system-level setup is silently performed. Keep a category UNVERIFIED until its real target can run.
