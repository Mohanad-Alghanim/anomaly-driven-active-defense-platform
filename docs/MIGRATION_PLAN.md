# Migration plan: rule-based external-attack detector → unsupervised insider-threat platform

Base code: `j7777f-gif/anomaly-driven-active-defense-platform` @ `ac3e4a4` (fast-forwarded onto this
repository; it was one commit ahead of `aafb5cd`). Final home: `Mohanad-Alghanim/anomaly-driven-active-defense-platform`.

## Non-negotiable principles

1. **No rules.** No "X events in Y seconds = attack" logic and no hand-written thresholds anywhere.
2. **Unsupervised only.** The model learns from normal behaviour and produces a continuous anomaly score. No supervised classifiers.
3. **The employee is the unit.** The main view is a list of `EMP` ids ranked by risk; selecting one explains the score.
4. **Every boundary comes from data.** Low/medium/high are quantiles of the score distribution of independent normal behaviour.
5. **No leakage.** No identifier, name, label, severity, scenario, provenance or IP in the model matrix. `Ground_Truth_Evaluation` is read for evaluation only.
6. **A perfect score is a failure signal.** Stop, diagnose and report.

## Keep

| Component | Files | Notes |
| --- | --- | --- |
| Streamlit dashboard shell | `app.py`, `.streamlit/config.toml`, `start.sh` | Phase 2 replaces the content with the employee risk list. The page layout, theme and launch script stay. |
| Log collection | `monitor/collectors.py`, `monitor/journal.py`, `monitor/adapters.py`, `monitor/worker.py` | Durable cursors, bounded reads, Journal adapter, single-writer lock. Phase 2 makes adapters emit the dataset event schema. |
| SQLite storage and history | `Engine` storage parts of `monitor/core.py` (schema, WAL, capacity limits, `state`, `rows`), `config()` validation of storage/source keys | The detection logic in `Engine.process` is removed (see below). Storage is kept. |
| Loopback lab environment | `monitor/lab.py` (HTTP target, disposable catalog, file watch), `monitor/lab_setup.py`, `monitor/lab_readiness.py` | Retargeted in Phase 3 to the six insider scenarios. |
| systemd user services | `deploy/*.service.in`, `monitor/install.py` | The unchanged collector/dashboard/lab units. |
| Test suite infrastructure | `tests/test_autonomous.py`, `tests/test_lab_delivery.py`, `tests/test_monitor.py` | Tests of storage, collectors, deployment and lab health are kept. Tests that assert rule alerts are rewritten in Phase 2. |
| Demo isolation | `monitor/demo.py`, `monitor/fixtures.py` | Kept as a concept (a separate `demo.db`). The external-attack demo events are replaced with insider-scenario events in Phase 2. |

## Delete

| Item | Location | Status |
| --- | --- | --- |
| Decision-tree "AI" engine | `monitor/ai_engine.py`, `monitor/ai_training.py`, `models/ai_engine/decision_tree.joblib`, old `models/ai_engine/metrics.json` | **Done in Phase 1.** The old metrics reported accuracy = 1.0, which is itself a leakage signal. |
| "AI Security Analyst" panel bound to the tree | `app.py` | **Done in Phase 1.** It is removed so the app does not import a deleted module. |
| Threshold rule engine | `monitor/core.py`: `CATEGORIES`, `ACTIONS`, `SQL`, `PRIV` regexes, `ssh_count/ssh_window/port_count/port_window/dos_count/dos_window` defaults and validation, all `hits.append(...)` logic, beaconing heuristic, severity mapping | Phase 2, step 1. It is removed together with wiring the brain into `Engine.process`, so the collector never runs without a detector. |
| Threshold keys in configuration | `config.example.json`, `config.lab.example.json` | Phase 2, together with `core.py`. |
| SSH brute force / port scan / DoS everywhere | `monitor/ssh_lab.py` (whole file), `monitor/lab_test.py` (SSH, port, DoS runners), port-scan listeners `SCAN_PORTS` and isolated OpenSSH in `monitor/lab.py`/`lab_setup.py`, `monitor/views.py` `coverage()` category table, `tests/test_ssh_penalties.py`, rule assertions in tests | Phase 2 (detector, views) and Phase 3 (lab scripts). |
| Rule-era dataset page | `monitor/dataset_analysis.py` (reads an old workbook with a `Detection_Rules` sheet) | Phase 2 (UI). |
| "Rule-based" wording | `app.py` caption, `README.md`, `TESTING_GUIDE.md`, `docs/VALIDATION.md`, `docs/LAB_TELEMETRY.md`, `docs/TROUBLESHOOTING.md` | Phase 2 (UI and docs). |

## New: the brain (Phase 1, done; awaiting approval)

`monitor/brain/` replaces `ai_engine.py`/`ai_training.py`:

| Module | Responsibility |
| --- | --- |
| `schema.py` | The 13 approved base features plus 6 personal-deviation features, and a leakage guard that rejects any other column. |
| `dataset.py` | Workbook loader with strict separation: features and attribution context (`source_ip → Device_Profiles → employee_id`) in one loader, labels in a separate evaluation-only loader. Chronological 70/15/15 split of normal events. |
| `features.py` | Per-employee baselines fitted on training normals: z-scores for bytes in/out, response time and activity; circular hour deviation; Laplace-smoothed service rarity. |
| `model.py` | Fitted pipeline (median impute + scale, one-hot categoricals) feeding an `IsolationForest`. Continuous scores, level boundaries from calibration quantiles, per-employee daily risk (summed `-log10` normal tail probability), employee ranking, and per-event explanations. |
| `evaluate.py` / `train.py` | AUROC, AUPRC, recall at 1% FPR, per-category results, session-grouped bootstrap CIs, univariate feature audit, employee-day evaluation, ablations. Writes `models/ai_engine/metrics.json`. |

Run with `.venv/bin/python -m monitor.brain.train`. Results and findings are in `docs/PHASE1_BRAIN_REPORT.md`.

## Roadmap (not started; each phase waits for approval)

* **Phase 2:** remove the rule engine and wire the brain into the collector and `Engine.process`. The home page becomes the employee risk list, with an "AI analysis" panel that explains each score in plain language.
* **Phase 3:** six insider-attack scripts on Kali (exfiltration, privilege escalation, SQL injection, out-of-role snooping, credential misuse, sabotage/log tampering). Each impersonates a real employee device IP from `Device_Profiles` and emits the dataset schema.
* **Phase 4:** active defense. When an employee's risk crosses the data-derived high boundary, respond (block IP / end session). The trigger is the score, never a rule.
