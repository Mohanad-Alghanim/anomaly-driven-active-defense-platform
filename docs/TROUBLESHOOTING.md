# Troubleshooting and recovery

## Start or restart without a terminal

Use **Active Defense Platform — Start Monitoring** or **Restart Monitoring**; each asks before enabling or
restarting the localhost services. **Component Health** shows service and target state. History is preserved
across failures; **Stop Monitoring** stops only this project's processes.

```bash
systemctl --user status active-defense-lab.service active-defense-collector.service active-defense-dashboard.service
journalctl --user -u active-defense-collector.service -n 50 --no-pager
```

## "Detection model unavailable" or collector ERROR

The collector refuses to store unscored events. If `models/ai_engine/insider_brain.joblib` or
`models/ai_engine/directory.json` is missing or cannot be loaded, the collector health shows the error and
ingestion waits.

Check that `requirements.txt` versions are installed: the artifact is a pickle tied to the pandas and scikit-learn
versions it was trained with. Alternatively, retrain with `.venv/bin/python -m monitor.brain.train` (this needs the
dataset workbook in `data/`). Restart the collector after changing the model; the dashboard shows the model version
in the collector banner.

## Employees not appearing

Only events whose source address belongs to a device in the directory are attributed and ranked. Other events are
still scored and listed under **Unattributed events**. Phase 3 scripts must use a real device IP from
`Device_Profiles`.

## Upgrading from the rule-based version

* Old `config.local.json` threshold keys (`ssh_count`, `port_count`, `dos_count`, …) are discarded on load.
* `--prepare-lab` removes the retired lab sources (`ssh-auth.log`, `connections.jsonl`, `privilege.jsonl`) and adds the telemetry inbox. A backup of the previous configuration is kept.
* Existing databases migrate additively. Old rule alerts stay in their tables but are no longer shown.
* The isolated SSH daemon and port-scan listeners are no longer started. Restart the lab service once after upgrading.

## WorkingDirectory quotation

Unit files render `WorkingDirectory=/absolute/path` without quotes; paths with spaces and percent signs are escaped
and covered by tests.

## Port conflict

The lab web target uses loopback port 8088 and the dashboard uses 8501. Startup fails rather than killing an
unrelated process; resolve the conflict deliberately, then restart.

## Capacity or rotation

At the configured event or database cap, ingestion pauses visibly rather than deleting history. Archive
deliberately, then raise the limit or use a new data directory. Lab logs rotate at 8 MiB with three generations.
