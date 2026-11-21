# Phase 1 report: the insider-threat brain

Dataset: `Behavioral_Intelligence_Dataset_INTERNAL_ATTACKS_6_CLEANED.xlsx` (synthetic). It is placed locally in
`data/`, which Git ignores. Reproduce with `.venv/bin/python -m monitor.brain.train`; the run is deterministic.
Full numbers are in `models/ai_engine/metrics.json`.

## Protocol

* **Training:** the earliest 70% of `Normal_Behavior_Learning` by time (42,000 events, before 2026-10-22 07:44 UTC).
* **Calibration:** the next 15% (9,000 normal events). The level boundaries are quantiles of these scores: medium = P95 (5% false-positive budget) and high = P99 (1%).
* **Evaluation:** the last 15% of normal events (9,000, from 2026-11-04 11:10 UTC) plus attack events. Labels are loaded from `Ground_Truth_Evaluation` only after the model and its boundaries are frozen.
* **Attribution:** each event's `source_ip` is matched to `Device_Profiles` to get the `employee_id`, as a live collector would. This resolves 100% of events. `Feature_Entity_Mapping.employee_id` is not used, because it is empty exactly for attack rows, so it would encode the answer.
* **Personal baselines:** recomputed from the training window only. The workbook's `Employee_Behavior_Baselines` cover all 60,000 normal events, including the held-out window. The schema is the same (mean/std per employee); the statistics are computed in log space.

## Results (main model: 13 base + 6 personal features)

| Evaluation set | AUROC | AUPRC | Detected at 1% FPR (high level) | Realized FPR |
| --- | --- | --- | --- | --- |
| All 2,168 attacks vs held-out normals | **0.9972** [0.9958–0.9984] | 0.9914 [0.9878–0.9945] | **96.7%** [95.5–97.9] | 1.16% |
| Strict chronological window (515 attacks) | 0.9972 | 0.9739 | 96.5% (precision 82.7%) | 1.16% |

95% intervals come from a bootstrap that resamples whole attack sessions.

| Category | AUROC | Detected at high level | Base-13 model, detected at 1% FPR |
| --- | --- | --- | --- |
| Credential Misuse | 0.9944 | 94.2% | 38.5% |
| Data Exfiltration | 0.9992 | 98.6% | 56.6% |
| Data Snooping | 0.9995 | 99.2% | 69.3% |
| Privilege Escalation | 0.9961 | 95.9% | 49.4% |
| SQL Injection | 0.9978 | 96.4% | 64.5% |
| Sabotage / Log Tampering | 0.9966 | 96.1% | 44.6% |

The base-13 Isolation Forest reproduces the reference baseline: AUROC 0.978, 53.8% detected at 1% FPR, with
behavioural categories around 0.4–0.6. The personal-deviation features raise every category above 94%.

**Employee output:** `models/ai_engine/employee_risk_heldout_window.csv` ranks all 1,000 employees for the held-out
window. Each row has the peak daily risk, its data-derived level, its percentile against normal employee-days, the
worst day, and the number of high-level events. The 13 employees who had attacks in the window rank 1 to 13.

## Findings that need your decision

### 1. Employee-day AUROC = 1.0: perfect-score alert (principle 6)

This is **not a leak**: no identifier or label reaches the model. The **number of events per employee-day alone**
also gives AUROC 1.0. In the held-out window, normal employee-days have at most 7 events, while every attack day
has at least 8. The dataset gives each employee exactly 60 normal events over about 90 days, while attack scenarios
are dense bursts (about 20 events every 3 seconds). Any volume-aware aggregation separates them perfectly, so this
number measures the generator, not detection skill. The training script now detects and reports this automatically
(`perfect_score_alerts`).

### 2. The detection gain comes mostly from dataset artifacts

| Ablation | AUROC | Detected at 1% FPR |
| --- | --- | --- |
| Main model | 0.9972 | 96.7% |
| Without `destination_port` | 0.9983 | 97.7% |
| Without port **and** burst volume (`source_events_previous_hour`, `emp_activity_z`) | 0.9736 | 45.6% |
| Base 13 | 0.9783 | 53.8% |

* **`destination_port`:** in normal data the port is random relative to the service (53/443/445/1194/5432 appear for every service). Attacks always use the service's canonical port. Ports 22, 389, 8088 and 8443 never occur in normal traffic, so 52.8% of attacks carry a port never seen in training. Dropping the port slightly *improves* the model. **Recommendation:** remove it from the model matrix.
* **Burst volume, bytes and response time:** univariate AUROC is 0.985–0.987 for activity, 0.975 for `bytes_in` and 0.969 for response time. All six categories share an identical generated profile (`bytes_in_log1p` ≈ 9.8, `source_events_previous_hour` ≈ 33–37, never on weekends), so the categories are distinguishable from normal but not from each other. Without the burst signal, every category drops to 40–49%.
* **Destination IPs** of attacks are never among the 8 servers in `Server_Profiles` (normal: 100%). IPs are excluded by principle 5, so this signal is unused. It is reported for completeness.

**Conclusion:** the pipeline meets the acceptance criteria, but on this dataset the high numbers mainly reflect how
the attacks were generated. Phase 3 should generate attack telemetry that matches normal volume and ports, so that
the personal-behaviour features are tested on their own merit.

## Acceptance checklist

* No hand-written attack threshold: the only fixed numbers are the false-positive budgets (5% / 1%). Score boundaries are quantiles of normal calibration data.
* No identifier, label or IP in the matrix: enforced by `schema.assert_no_leakage` on every fit and score, and covered by tests.
* No supervised model: `DecisionTreeClassifier` and its files are deleted. A test scans `monitor/brain/` for supervised estimators.
* AUROC ≥ 0.98: met (0.9972).
* A score per employee: met (CSV ranking plus `InsiderThreatBrain.employee_risk`).
