# Six-Attack SOC — bounded local lab tests

## Delivery status and one-time activation

The lab targets, native telemetry producers, source configuration, watched file, isolated SSH host key, user-service file and graphical controls have been provisioned in `/home/kali/six-attack-security-monitor`. The existing live database, working host SSH detection and manually repaired dashboard/collector units are preserved.

**Latest validation status:** the user's full real-lab verification passed the other five categories. SSH remained UNVERIFIED because per-source penalties dropped the fifth client before authentication. The correction below disables penalties only for the isolated daemon and verifies native failure records, collection and a new alert. This development sandbox still blocks sockets and cannot see the isolated daemon PID, so the corrected SSH live retest remains UNVERIFIED here. The five existing verified results are preserved.

One-time action on the Kali desktop:

1. Open **Start SOC Lab and Monitoring** from the applications menu or desktop.
2. Approve its explicit confirmation to start/restart this project's user services and enable login startup. It starts loopback targets only; it runs no attack tests. Existing host SSH on port 22 is not changed.
3. Wait several seconds, then open **SOC Lab Component Health** and **Six-Attack SOC** (`http://127.0.0.1:8501`). Refresh an already open browser after this upgrade.
4. Confirm that the lab, collector and dashboard are running. The six-category panel keeps target/source health separate from VERIFIED/UNVERIFIED test evidence.
5. Run the commands below in a **separate normal-user terminal**, never with sudo.

All required binaries for this Kali environment were found: Python, OpenSSH server/client, ssh-keygen, sshpass, curl and nmap. No system packages, firewall rules, packet capture or host SSH changes are needed here. `/run/sshd` exists and the private lab configuration passes `sshd -t`. A different machine missing those components requires one-time administrator-approved installation/setup; the application does not attempt privileged changes automatically.

```bash
cd /home/kali/six-attack-security-monitor
```

No per-attack source configuration or manual log import is required. Configuration was merged once into ignored `config.local.json`, with a private backup. The wrappers below produce **actual activity**, not synthetic JSONL insertion. They wait for a quiet prior rule window when needed, generate bounded traffic, and require a **new alert from the exact lab source** to report success. A recent historical alert or unrelated host event cannot satisfy the check.

Normal controls and all-category verification are available after activation:

```bash
.venv/bin/python -m monitor.lab_test normal
.venv/bin/python -m monitor.lab_test verify
```

`normal` waits for preceding SSH/port/HTTP windows to clear. `verify` first checks benign activity for unexpected lab alerts, then explicitly runs the six bounded tests and writes private evidence to `runtime/lab/validation.json`. Nothing runs these commands at login. Allow several minutes for the bounded quiet-window waits. `PIPELINE VERIFIED` means actual activity reached the collector, persisted alert and dashboard read model; personally review Firefox too. Browser visuals are not proved by a database check.

## 1. SSH Brute Force

**Exact target:** isolated OpenSSH at `127.0.0.1:2222`. This is separate from the existing host SSH service on port 22.

**Prerequisites:** lab SSH component RUNNING; sshpass and ssh installed (confirmed here); collector running. The managed daemon binds only loopback, uses its own private host key, disables PAM/forwarding/root login and allows only the reserved **nonexistent** username `six-soc-invalid`. No real user account is created or used. The daemon cannot provide a useful login shell.

Before the first SSH retest after this correction, apply/reload **only the isolated SSH daemon**:

```bash
.venv/bin/python -m monitor.ssh_lab --apply
.venv/bin/python -m monitor.lab_test ssh
```

`--apply` migrates only the exact previous managed `runtime/lab/sshd_config`, backs it up privately and checks it with `sshd -t` before replacement. The isolated daemon now has **`PerSourcePenalties no`**, supported by the installed OpenSSH 10.5p1. This exception applies only to the loopback test daemon at port 2222. Host `/etc/ssh` configuration, firewall settings, detector thresholds and other lab targets are not changed.

Reload uses a pinned PID descriptor and checks the process owner, OpenSSH executable and exact private config path before sending SIGHUP. If the PID is missing, inaccessible or mismatched, no signal is sent. Run this command from the ordinary Kali terminal, where the daemon is visible, if the development sandbox reports `No such process`. A reload request is not itself validation success.

The bounded test makes **up to ten client attempts in at most 60 seconds**, stopping immediately once at least **five new actual `Failed password` records** are observed. The detection threshold remains **five failures in 60 seconds**. Its literal password is deliberately invalid, not a stored credential. Each client has a timeout; the server limits unauthenticated connections and sessions.

Only new native records for `six-soc-invalid` from `127.0.0.1` count. Earlier records, partial lines, client return codes, connection attempts, timeouts, `srclimit_penalise` messages and `drop connection ... penalty: failed authentication` messages do **not** count. Rotation is handled without recounting the same record. Four actual failures plus a dropped fifth connection is UNVERIFIED; if the sixth client produces the fifth real failure, the test stops there.

Before reporting success, the runner confirms five corresponding SQLite events with `kind=ssh_failed` and `ip=127.0.0.1`, within the 60-second window. It then requires a new **SSH Brute Force / ABNORMAL / HIGH** alert linked to those native failures and present in the dashboard read model. The single SSH command updates only SSH's private validation result, preserving the other five results on success or failure.

**Expected telemetry:** actual OpenSSH `Failed password` records in `runtime/lab/ssh-auth.log`; the auth adapter normalizes these automatically. **Default threshold:** five failures from `127.0.0.1` within 60 seconds. **Expected alert:** SSH Brute Force / ABNORMAL / HIGH, destination `127.0.0.1:2222`, rule and SSH access recommendations. Earlier contributing records remain NORMAL until the rule triggers.

**Verify:** wrapper prints a new alert ID; select SSH Brute Force in Firefox and inspect event/detection timestamps, source, destination and recommendation. Do not count the older host-SSH alert as this target's validation.

**Stop:** the command ends after five confirmed failures or at the ten-attempt/60-second limit; Ctrl+C stops it early. No continuous brute-force tool remains running.

**Recover:** review `runtime/lab/ssh-auth.log` and run `monitor.ssh_lab --apply` to reload only the isolated daemon. Confirm `PerSourcePenalties no` in its private config; do not lower the five-in-60 threshold. If the reload fails, SSH remains UNVERIFIED. Use SOC Lab Component Health to inspect services. A missing `/run/sshd` on another machine needs administrator-approved repair; do not change normal SSH settings to compensate. A reserved-name collision or modified managed SSH config fails closed and must be reviewed once.

## 2. Port Scanning

**Exact target:** twenty TCP listeners at `127.0.0.1:9100–9119`. **Prerequisites:** connections component and collector RUNNING.

```bash
.venv/bin/python -m monitor.lab_test scan
```

The command makes exactly twenty TCP connections, with a short pause and timeout per connection, then closes them. Alternative bounded scan using installed nmap:

```bash
nmap -sT -Pn -n --max-retries 0 --max-rate 10 --host-timeout 10s -p 9100-9119 127.0.0.1
```

Use **TCP connect (`-sT`)**, not SYN-only scanning. The target records actual accepted connections; it is not packet capture and cannot see arbitrary scans of unrelated host ports.

**Expected telemetry:** actual peer/source port and local destination port from the accepted sockets, automatically written to `runtime/lab/connections.jsonl`. This native target log is generated by network activity, not by manually appending test fixtures. **Default threshold:** 15 distinct ports from the same source in 60 seconds. **Expected alert:** Port Scanning / ABNORMAL / MEDIUM with source/destination details and firewall review recommendation.

**Verify:** observe the new alert ID and Port Scanning filter. One connection to one port is a normal control; multiple attempts to the same port do not satisfy the distinct-port threshold. Repeat tests should use the wrapper, which waits for the previous window/cooldown.

**Stop:** command exits after twenty connections; Ctrl+C closes the active client. **Recover:** check the connections component and collector health, then restart through the graphical control. A port conflict is reported; this software never kills the unrelated listener or silently changes target ports.

## 3. SQL Injection

**Exact target:** `http://127.0.0.1:8088/search?q=...`. **Prerequisites:** web component and collector RUNNING.

```bash
.venv/bin/python -m monitor.lab_test sql
```

The wrapper sends one request containing `' OR 1=1 --` and checks the real disposable SQLite query result. An equivalent single request for manual observation is:

```bash
curl --max-time 3 --get --data-urlencode "q=' OR 1=1 --" http://127.0.0.1:8088/search
```

The deliberately unsafe query exists **only** in this in-memory toy catalog containing `pencil` and `notebook`. There are no credentials or host data in it, no database-file input, no extension loading and no multiple SQL statements. Query length and execution steps are bounded. A normal query for `pencil` returns one row; this injection returns both rows.

**Expected telemetry:** actual HTTP access record in `runtime/lab/access.log`; request text is URL-decoded by the existing adapter. **Threshold:** one predefined SQL pattern match. **Expected alert:** SQL Injection / ABNORMAL / HIGH, destination `127.0.0.1:8088`, SQL rule/explanation and parameterized-query recommendation.

**Verify:** wrapper requires a new SQL alert from the lab access log; inspect its request and both timestamps in Firefox. The normal control request contains no SQL pattern and should remain NORMAL outside a preceding DoS window.

**Stop:** one request only; Ctrl+C or curl's timeout stops it. **Recover:** restart the lab graphically if the web component is stopped. A direct SQLite unit test passing does not prove HTTP collection; inspect live source status and actual access-log advancement.

## 4. Denial of Service (DoS) indicator

**Exact target:** `http://127.0.0.1:8088/health`. **Prerequisites:** web component and collector RUNNING; no other test in progress.

```bash
.venv/bin/python -m monitor.lab_test dos
```

At defaults this sends **52 sequential lightweight HTTP requests**, then stops. The wrapper refuses configurations requiring more than 64 requests and reports failure if it cannot reach the configured time window. It does not attempt to exhaust the VM or disrupt real applications; this is a bounded request-rate test.

**Expected telemetry:** one actual access record per request in `runtime/lab/access.log`. **Default threshold:** 50 requests from one IP in 10 seconds. **Expected alert:** Denial of Service (DoS) / ABNORMAL / MEDIUM, source `127.0.0.1`, destination `127.0.0.1:8088`, rate rule and rate-limiting recommendation. Repeated matches within the cooldown remain ABNORMAL without generating duplicate alerts.

**Verify:** new alert ID and DoS category in Firefox. A single health request during a quiet period is the normal control. Rate matches are indicators, not evidence of actual service unavailability.

**Stop:** the command stops after the bounded count; Ctrl+C stops it earlier. **Recover:** wait for the previous HTTP window to expire (the wrapper does this), verify access-log source health, then restart through the graphical control if needed. Do not increase test traffic to troubleshoot a stopped collector.

## 5. Unauthorized File Modification

**Exact target:** `/home/kali/six-attack-security-monitor/runtime/lab/watched/settings.txt`. **Prerequisites:** background collector running and baseline recorded. The network target process is not required for file integrity checks.

```bash
.venv/bin/python -m monitor.lab_test file
```

The wrapper changes this explicitly selected lab file, waits for its new alert, then restores the approved baseline in a `finally` block. It never edits a system file or real application configuration.

**Expected telemetry:** actual content-hash difference observed by the background file monitor. **Threshold:** one changed content hash not matching the configured approved SHA-256. **Expected alert:** Unauthorized File Modification / ABNORMAL / HIGH, destination/path set to the lab file, rule and trusted-restore recommendation. Restoring the known approved baseline is NORMAL and should not generate a second alert.

**Verify:** new alert ID and exact file path in Firefox. This path was validated against the existing running collector and the **main live database**, and rendered successfully by Streamlit AppTest during delivery. Actual Firefox visuals remain a desktop check.

**Stop:** normally automatic restoration; Ctrl+C also enters the cleanup block. **Recover:** if a hard kill/power loss interrupted cleanup, run this safe local restoration once, then allow a collector poll:

```bash
.venv/bin/python -c "from pathlib import Path; from monitor.lab_setup import BASELINE,paths; paths(Path.cwd())['watched'].write_bytes(BASELINE)"
```

Do not clear the database or delete cursor state to repeat a test.

## 6. Suspicious Privilege Escalation indicator

**Exact target:** the local OS capability boundary of a fresh **unprivileged** test process. No sudo policy, PAM rule, account, group or setuid executable is modified. **Prerequisites:** normal non-root user; collector restarted once after this upgrade (`rules_version=3`); prepared native audit source.

```bash
.venv/bin/python -m monitor.lab_test privilege
```

The probe confirms it has no `CAP_SETUID` capability in its effective/permitted sets, then makes a real Linux `capset` request to add that capability. Linux denies the request with `EPERM`; the producer logs the actual return code. If it already has the capability, is root, or receives an unexpected result, the probe refuses/fails rather than pretending to validate a denial. The request affects only the caller; no privilege is granted in the verified path.

This is an instrumented, authentic **denied privilege-boundary test**, not a successful privilege exploit and not a claim of comprehensive kernel audit coverage. The local native log is `runtime/lab/privilege.jsonl`, automatically produced from the OS result. It is not a fabricated fixture or manually appended security event.

**Threshold:** one predefined `LAB_PRIVILEGE_DENIED operation=capset capability=CAP_SETUID errno=1` match. **Expected alert:** Suspicious Privilege Escalation / ABNORMAL / HIGH, source IP unavailable, destination identifying the local permission boundary, with rule/explanation and privilege-review recommendation. A normal `getuid` call is logged as NORMAL. Existing sudo/su Journal handling is preserved.

**Verify:** wrapper requires a new alert from this exact native audit source. During delivery, the real denial traversed a real independent collector process, SQLite and the Streamlit renderer in an isolated validation database. The existing production collector still needs a restart to load the added rule; that production path and Firefox remain UNVERIFIED until tested on the desktop.

**Stop:** one immediate system call; process exits with no persistent privilege change. **Recover:** use **Restart SOC Lab and Monitoring** once to load the new rule. A non-EPERM return or unsupported capability interface is UNVERIFIED, never success. Do not run the probe as root to make it pass.

## Health, shutdown and recovery

- **SOC Lab Component Health** shows service states and lab heartbeat.
- **Start SOC Lab and Monitoring** starts/restarts the three project services and enables them for future user logins, after confirmation.
- **Stop SOC Lab and Monitoring** stops only this project's dashboard, collector and lab (including child SSH), preserving history. Enabled units resume at next login. It leaves the host SSH service untouched.
- **Restart SOC Lab and Monitoring** recovers failed project components after confirmation. No attack test runs as part of recovery.
- Closing Firefox does not stop collection. Shutting down the VM stops everything; there is no monitoring while powered off. User logout normally stops user services; linger is not enabled.

Optional administrator diagnostics, not required before each test:

```bash
systemctl --user status six-soc-lab.service six-soc-collector.service six-soc-dashboard.service
journalctl --user -u six-soc-lab.service -u six-soc-collector.service -n 50 --no-pager
```

Do not expose these intentionally instrumented targets outside loopback. Do not run test commands against any external IP. If port conflicts, missing host components, denied user-bus access or sandbox restrictions persist, the readiness state must remain UNVERIFIED rather than being inferred from demonstration results.
