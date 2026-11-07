# Optional external telemetry adapters

The bundled local lab is provisioned automatically with `monitor.install --prepare-lab`; see the root TESTING_GUIDE.md. The following is advanced documentation for additional existing sources, not per-test setup for the bundled lab.

The application is a consumer of telemetry. A successful lab request or test is visible only if the designated target records an event in a configured source. Monitoring does not enable SSH, capture packets, change firewall logging, create a web target, or expose a new ingestion endpoint.

## Authentication Journal on Kali

The default background collector queries existing `sshd`, `sshd-session`, `sudo` and `su` identifiers as the normal Kali user. It does not use `sudo journalctl`, and it does not require `/var/log/auth.log`. Normal sudo/su session records are retained as NORMAL unless a predefined suspicious rule matches.

Journal cursor and last event time live in the same SQLite database as event state. On restart, the reader requests entries after the saved cursor in oldest-first order and reads bounded batches. If a cursor has expired, it replays from the last saved timestamp minus two seconds, using cursor-based event IDs to deduplicate overlap. First start reads a configurable five-minute lookback. Records removed by Journal retention cannot be recovered. Access restrictions are reported; a successful empty query does not establish that all system authentication logs are visible.

SSH being installed does not mean it is running. If it is inactive, SSH tests will not generate the expected authentication events. Enabling an SSH lab target is a separate operator-approved step outside this application's deployment. For SSH tests against another machine, provide that target's records; Kali's Journal will not automatically contain them.

## Firewall / connection telemetry

Select an existing log file using `format: "netfilter"`. The adapter expects existing UFW/netfilter messages containing `SRC=`, `DST=` and `DPT=`; `SPT=` is optional. It understands traditional local syslog timestamps or an ISO timestamp at the start of a line. A SYN/connection-attempt log policy is preferable to logging every packet, since packet-level duplicates may distort request interpretation.

Optionally set `journal.kernel_netfilter: true` **only when kernel firewall messages are already present in the Journal**. This adds a read-only kernel-identifier query; it does not enable firewall logging. Non-netfilter kernel messages are rejected and counted. A file containing only firewall policy changes, or a host without connection telemetry, cannot support the port-scanning rule.

We do not create firewall rules or introduce packet capture. Have your lab administrator approve and arrange any missing telemetry separately. A file becoming readable is not validation that a port scan is correctly observable.

## HTTP request telemetry

Select an existing Apache/Nginx common or combined access log using `format: "http_access"`. One request record becomes one HTTP event. Provide `destination` (host/target label) and optional `destination_port` so the dashboard identifies the target. Requests are URL-decoded once for the SQL pattern check.

The adapter uses the recorded client IP. Behind a reverse proxy, that may be the proxy address; configuring a trustworthy client-IP logging policy is the operator's responsibility. Custom web log formats, JSON web logs, application request bodies, and nonstandard timestamps need an appropriate existing exporter or normalization to JSONL.

SQL rules flag predefined request strings. DoS rules flag the configured count of HTTP records per source IP/window. Neither consumes SSH records. Source logs must have enough time resolution and complete request coverage to support the intended rate threshold.

## Normalized JSONL from existing tools

Use `format: "jsonl"` and declare `kinds` for coverage reporting. Each record is a JSON object with:

```json
{"ts":1794042000.0,"kind":"connection","ip":"192.0.2.10","source_port":44000,"dst_ip":"192.0.2.100","dst_port":8080,"message":"Synthetic connection attempt"}
```

Required fields: numeric Unix `ts`, supported `kind`, string `message`. Supported kinds: `normal`, `ssh_failed`, `connection`, `http`, `file`, `privilege`. Optional fields: `ip`, `source_port`, `dst_ip`, `dst_host`, `port`/`dst_port`, `authorized`. Ports must be valid integers; connections require a destination port. Imported event IDs are derived from file path/inode/offset/content so repeated identical lines at different offsets remain separate real attempts, while restart replay is idempotent. The original JSON `id` is deliberately not trusted by the file collector.

Append complete newline-terminated records. Supply events in timestamp order, with synchronized lab clocks. Ordering across different source files is not globally merged. For a single rule, prefer one authoritative source stream per target; duplicates from multiple independent telemetry feeds are not semantically deduplicated. The threshold engine groups by source IP, so records from different configured targets sharing an IP can contribute to the same window.

No external tool is automatically installed or enabled. If logs originate remotely, use an already approved shared file or log delivery mechanism. Protect these files using normal user/group access; do not make sensitive authentication logs world-readable.

## File integrity

Add only explicitly selected test paths to `files`. First observation creates a baseline. Subsequent changes are hashed in bounded chunks up to `max_file_bytes` (32 MiB default). To authorize a specific new content version, add its SHA-256 as `authorized_sha256` **before** changing the file. An approved hash authorizes that content while configured, not an unlimited period of arbitrary editing.

File deletion/read failure is reported as source unavailability, rather than a seventh category. Metadata-only changes and transient changes reverted between polling intervals are outside this simple content monitor's scope.

## Safe delivery verification

`python -m unittest discover -s tests -v` processes `monitor.fixtures` synthetic data through Journal normalization (injected reader), raw access/firewall adapters, file-change detection, the background cycle, SQLite and the dashboard read model. Tests also launch/stop/restart an actual collector process against temporary log files without opening a browser.

Do not import fixtures into the production live database just to manufacture alerts. The built-in demonstration and automated tests keep simulated data separate. Fixtures are examples of formats, not evidence of real attacks. Perform actual authorised lab validation separately after source setup and service activation. Confirm each category using its appropriate telemetry, then review source and destination fields and both timestamps in the alert details.
