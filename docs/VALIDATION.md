# SSH penalty correction — latest verification

The installed OpenSSH is 10.5p1; its local sshd_config manual documents `PerSourcePenalties no`, and the installed daemon accepts the directive. Only the exact managed isolated-daemon configuration at `runtime/lab/sshd_config` was migrated (with a private backup). `sshd -t` passed before replacement and again afterward. The host SSH configuration, firewall, five-in-60 detection threshold, other five detectors, databases and working user services were not changed.

The corrected runner counts only new, complete native `Failed password` records for the reserved test user from 127.0.0.1, and permits at most ten clients / 60 seconds. It stops at five actual records, requires their five normalized SQLite events (`kind=ssh_failed`, loopback source IP), and requires a newly generated HIGH/ABNORMAL SSH alert linked to those records and present in the dashboard read model. It does not count client connection attempts or penalty drops.

**Actual corrected live result: UNVERIFIED.** The sandbox cannot access the isolated daemon's PID (`No such process` in its PID namespace), so no reload signal was sent. It also denies socket creation. The bounded retest made ten client attempts and observed **zero new native Failed password records**, so it correctly failed validation. The four previous lab failures remain present in both the native log and SQLite; there is **no new lab SSH alert**. The older real host SSH alert remains preserved. The independent collector heartbeat remained RUNNING.

The other five saved category results remain PIPELINE VERIFIED, consistent with the user's recent full verification. SSH-only success/failure reporting preserves those entries. No other-category live tests were rerun for this correction.

Automated regression results: **60 total, 58 passed, 2 skipped**. The skips remain real systemd-manager validation and opt-in live network verification. New tests cover the four-failures/penalty-drop/sixth-client case, stopping at five native records, ten drops/timeouts never passing, exclusion of old/partial/wrong-identity records, rotation/deduplication, native-log-to-SQLite correlation, a real collector/rule/read-model path using synthetic regression fixtures, strict threshold retention, safe config migration/parser failure, reload refusal for an unobservable PID, and preservation of the five already verified results. Fixtures are not represented as real SSH validation.

On the ordinary Kali terminal, run `monitor.ssh_lab --apply` with the project Python interpreter, then `monitor.lab_test ssh`. The apply command pins and verifies only the same-user isolated sshd master before SIGHUP; it does not restart the lab's HTTP/TCP targets, collector, dashboard or host SSH. Claim success only after the runner reports at least five native failures, five collected events and a new matching alert. See TESTING_GUIDE.md.

---

## Historical delivery evidence (superseded by the latest correction/results above)

# Final lab delivery evidence — 7 November 2026

## Overall status

**Acceptance is incomplete: new network targets and all-category production validation are UNVERIFIED.** All target code and native telemetry sources are provisioned, but the execution sandbox denies socket creation and systemd user-bus access. This report distinguishes real observed activity from unit fixtures and prepared components.

The existing main live database and working SSH alert were preserved. Installed collector/dashboard unit files already contain the manually repaired unquoted WorkingDirectory; the lab upgrade does not overwrite them.

## Six-category results

| Category | Actual evidence obtained | Remaining validation |
| --- | --- | --- |
| SSH Brute Force | Existing main live `journal:sshd` event/alert confirmed: ABNORMAL / HIGH, consistent with the user's successful real SSH test | New isolated loopback SSH target on 2222: UNVERIFIED; Firefox recheck after activation |
| Port Scanning | Native socket-accept target and automatic source configuration implemented | Actual TCP target → collector → alert: UNVERIFIED (socket restriction) |
| SQL Injection | Actual disposable SQLite query executes; normal query returns one row, bounded injected query returns both rows; stacked statement rejected | HTTP transport/access log → live alert: UNVERIFIED (socket restriction) |
| Denial of Service (DoS) | Instrumented HTTP target and bounded request runner implemented; deterministic rate rule tested | Actual HTTP requests → collector → alert: UNVERIFIED (socket restriction) |
| Unauthorized File Modification | Actual designated lab file was modified; existing independently running collector produced a new HIGH/ABNORMAL alert in **main live SQLite**; the actual dashboard rendered it through AppTest | Interactive Firefox display remains UNVERIFIED; approved baseline was restored |
| Suspicious Privilege Escalation | Actual Linux CAP_SETUID request denied with EPERM, native audit log read by a real independent collector process, alert persisted in isolated validation SQLite, actual dashboard rendered it through AppTest | Production collector restart/new-rule path and interactive Firefox: UNVERIFIED |

A separate real native validation also covered file integrity and denied capability events together through a standalone background collector process. Benign `getuid` activity generated no alert; restoring the approved file hash generated no extra alert. The validation collector stopped gracefully. This was actual syscall/filesystem activity, not appended synthetic security fixtures. Its private evidence/data are in ignored `.local-validation/`; only summary results are documented publicly.

No claim is made that the native privilege probe validates arbitrary privilege escalation, host auditd, PAM bypass, or a successful exploit. It validates an actual denied capability boundary and deterministic processing of that native audit event. No privilege was granted.

## Automated checks

- `.venv/bin/python -m unittest discover -s tests -v`: **45 total, 43 passed, 2 skipped**.
- All six rule categories, normal handling, thresholds/windows, cursor recovery, incremental ingestion, rotation, duplicate suppression, migration/persistence, concurrent SQLite access, process restarts, capacity reporting and dashboard rendering remain covered.
- Added provisioning idempotence/config preservation, real disposable SQL behavior, real denied capability and filesystem pipeline, live readiness evidence separation, graphical activation cancellation, repaired-unit preservation and unquoted WorkingDirectory regression coverage for all three service files.
- Generated unit text is structurally validated before write. Real `systemd-analyze --user verify` is explicitly skipped when manager/socket restrictions prevent it; structural checks are not represented as an actual systemd launch.
- The all-category live network integration test is explicitly opt-in (`SIX_LAB_NETWORK_TESTS=1`) and requires the already approved running lab. It was skipped here and does not count as a pass.
- Provisioned OpenSSH configuration: `/usr/sbin/sshd -t -f runtime/lab/sshd_config` **passed**, using the private newly generated key. This is a configuration check, not listener/authentication validation.
- `desktop-file-validate` on all four new lab graphical controls **passed**.
- `.venv/bin/python -m pip check`: no broken requirements.
- `git diff --check`: passed.

## Deployment and preservation

Confirmed via read-only main-database inspection: collector heartbeat was current, sources were automatically picked up after the one-time merge, and the previous real SSH alert remained present. The main live file alert was generated by that existing collector, without restarting it or replacing its user unit. No demonstration database was used for these real validations.

Prepared locally:

- Managed loopback SSH config and own Ed25519 key; no real user/account or password provisioned.
- Empty native target log files and an explicitly watched test file with approved baseline hash.
- One-time merged source definitions, with a private original-config backup.
- `six-soc-lab.service`, using unquoted WorkingDirectory, normal-user execution, NoNewPrivileges, restart backoff and resource limits.
- Graphical Start, Stop, Restart and Component Health controls, alongside the existing dashboard launcher.

The lab service was **not enabled or started** here. Existing working dashboard/collector units were not overwritten. Host SSH, firewall rules, packet capture, system packages, group membership and system security settings were not changed. No privileged host setup is required in the inspected environment; the missing step is user-approved activation on the ordinary desktop.

## Outstanding desktop acceptance

1. Open Start SOC Lab and Monitoring and approve the loopback-listener/startup confirmation.
2. Confirm the lab service, new SSH/HTTP/TCP targets, collector and dashboard are running.
3. Execute `.venv/bin/python -m monitor.lab_test verify` from the project directory. It performs bounded local activity only and requires a new alert from the correct source for each category.
4. Review all six alerts in Firefox, close/reopen Firefox to confirm independent collection, and test logout/login startup and graphical stop/restart.
5. Keep any unsuccessful category UNVERIFIED. Unit tests, historical host SSH alerts, an empty readable source or demo results must not substitute for these checks.

These steps could not be executed through the blocked user bus/network namespace in this development environment. The project is therefore delivered with implemented/provisioned components and explicit unresolved acceptance items, not falsely labelled fully operational.
