# Deployment migration validation — 8 November 2026

Official project title: **Development of an Anomaly-Driven Active Defense Platform Against Unauthorized Access and Credential Attacks**.

The deployed directory is `/home/kali/anomaly-driven-active-defense-platform`. Dashboard: http://127.0.0.1:8501. Firefox tab: **Anomaly-Driven Active Defense Platform**. Firefox validated the exact heading, readiness label and heading wrapping at 1440 and 390 pixel window widths.

All three user units are active and enabled under `default.target`: `active-defense-collector.service`, `active-defense-dashboard.service` and `active-defense-lab.service`. Previous units were stopped, disabled and removed before startup. A single collector owns the database lock. Loopback listeners retain their configured ports. Login startup links and systemd unit parsing were verified; an actual logout/login was not performed during monitoring.

The menu and Desktop each contain exactly five platform entries: the official academic title, plus Active Defense Platform — Start Monitoring, Stop Monitoring, Restart Monitoring, and Component Health. Obsolete managed entries were removed. Installation templates generate the new names.

The full suite passed **60 tests, zero skipped**, with `SIX_LAB_NETWORK_TESTS=1 .venv/bin/python -m unittest discover -s tests -q`. All six bounded local detection paths produced newly persisted alerts. These checks added six alerts, increasing the count from eight to fourteen. Private live evidence remains in `runtime/lab/validation.json`.

All original 203 event rows, eight alert rows and sixteen detection matches were checked byte-for-byte at the row level before restart and again as a subset after validation. SQLite integrity is OK. No historical event identity, payload, alert, rule, threshold or category changed. Operational cursor and hash state was copied to the relocated path keys to avoid replay and preserve baseline continuity. Old state keys remain available. Source logs retain their original byte prefixes. SSH host keys and watched-file baseline hashes are unchanged. The reserved invalid SSH test identity and historical baseline bytes are retained for compatibility.

Installed virtual environment packages were preserved. Activation paths and command shebangs were repaired, and imports from the relocated environment passed. No dependency upgrade was performed.

Private backups, including stopped database state, configuration, deployment entries, logs, keys and a Git history bundle, are stored at `/home/kali/active-defense-migration-backups/20261108` (owner-only directory). No private backup or live data is tracked in Git.

GitHub repository rename and repository description update require authenticated repository administration. The connected integration supports source delivery but does not expose those administration operations. The requested repository name is `anomaly-driven-active-defense-platform`; do not create a replacement repository.
