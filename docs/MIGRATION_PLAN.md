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

## Status

| Phase | State |
| --- | --- |
| 1. Brain (unsupervised model, data-derived levels, employee risk, evaluation) | **Approved and closed.** Port removed, count-free employee risk, full model reported next to the artifact-free floor. See `docs/PHASE1_BRAIN_REPORT.md`. |
| 2. Brain wired into collector; employee-first dashboard; rule engine removed | **Done, awaiting approval.** See `docs/PHASE2_INTEGRATION_REPORT.md`. |
| 3. Six insider-scenario scripts on Kali | Not started. |
| 4. Score-triggered active defense | Not started. |

## Kept

| Component | Files |
| --- | --- |
| Streamlit dashboard shell, theme, launcher | `app.py`, `.streamlit/config.toml`, `start.sh` |
| Log collection with durable cursors | `monitor/collectors.py`, `journal.py`, `adapters.py`, `worker.py` |
| SQLite storage, history, capacity limits, additive migration | `monitor/core.py` (storage parts) |
| Loopback lab (Internal Web target, watched file) plus new telemetry inbox | `monitor/lab.py`, `lab_setup.py`, `lab_readiness.py` |
| systemd user services and graphical controls | `deploy/*.service.in`, `monitor/install.py` |
| Test suite infrastructure | `tests/` |

## Removed

| Item | Phase |
| --- | --- |
| Decision-tree engine, training, model file, its UI panel | 1 |
| Threshold rule engine in `monitor/core.py` (categories, regexes, count/window thresholds, beaconing, cooldowns, severities) | 2, in the same change that made the brain the detector |
| Threshold keys in configuration (discarded on load from old files) | 2 |
| SSH brute force / port scan / DoS lab: `ssh_lab.py`, `lab_test.py`, `privilege_probe.py`, isolated OpenSSH, ports 9100–9119 | 2 |
| `views.coverage()`, category readiness, `dataset_analysis.py`, rule-era docs and fixtures, "Rule-based" wording | 2 |

## The brain (`monitor/brain/`)

| Module | Responsibility |
| --- | --- |
| `schema.py` | Approved model inputs (12 dataset features without the port, plus 6 personal deviations) and the leakage guard. |
| `dataset.py` | Workbook loader: features and attribution context only; labels through an evaluation-only loader. |
| `features.py` | Per-employee baselines from training normals (stored as numpy arrays, no pandas objects). |
| `model.py` | Pipeline + IsolationForest; event and employee levels from calibration quantiles; employee ranking. |
| `risk.py` | Rolling employee risk (time-decayed mean, count-free), shared by training, evaluation and the collector. |
| `telemetry.py` | Live normalization, attribution and feature derivation, matching the workbook to floating-point precision. |
| `explain.py` | Plain-language employee explanations. |
| `runtime.py` | Cached artifact loading, model version, pandas-free pickle check. |
| `train.py`, `evaluate.py`, `replay.py` | Training, evaluation, exports, parity check, replay to JSONL. |

## Roadmap (each phase waits for approval)

* **Phase 2.5 (done):** Kali environment pinned; model retrained on Kali and made pandas-version independent. See [PHASE2_5_KALI_ENVIRONMENT_REPORT.md](PHASE2_5_KALI_ENVIRONMENT_REPORT.md).
* **Phase 3:** six insider-attack scripts on Kali (exfiltration, privilege escalation, SQL injection, out-of-role snooping, credential misuse, sabotage/log tampering). Each impersonates a real employee device IP from `Device_Profiles`, writes the behavioural schema to `runtime/lab/telemetry.jsonl`, and keeps volume and ports close to normal (stealth requirement).
* **Phase 4:** active defense. When an employee's risk crosses the data-derived high boundary, respond (block IP / end session). The trigger is the score, never a rule.
