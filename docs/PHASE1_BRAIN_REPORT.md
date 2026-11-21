# Phase 1 report: the insider-threat brain (final, frozen)

Dataset: `Behavioral_Intelligence_Dataset_INTERNAL_ATTACKS_6_CLEANED.xlsx` (synthetic; kept locally in `data/`,
which Git ignores). Reproduce with `.venv/bin/python -m monitor.brain.train`; the run is deterministic. All numbers
below are in `models/ai_engine/metrics.json`.

## Headline: two numbers, always reported together

| | AUROC | AUPRC | Detected at 1% FPR | Realized FPR |
| --- | --- | --- | --- | --- |
| **Full model** (17 features) | **0.9983** | 0.9948 | **97.7%** | 1.14% |
| **Artifact-free floor** (without burst volume) | **0.9736** | 0.8833 | **45.6%** | 1.24% |

The full model benefits from two dataset artifacts. The floor is the honest estimate without them. Neither
number establishes real-world detection performance.

### The two artifacts

1. **`destination_port`.** In normal data the port is random relative to the service (53/443/445/1194/5432 occur for
   every service). Attacks use the canonical service port, and 22/389/8088/8443 never occur in normal traffic.
   **Decision, made in principle before the final training run:** the port is removed from the model matrix. It is a
   generation artifact with no behavioural meaning, and "normal traffic uses a random port per service" is not
   realistic in the first place. The port is still stored and shown as context.
2. **Burst volume on a sparse normal baseline** (`source_events_previous_hour`, `emp_activity_z`). Each employee has
   only 60 normal events in about 90 days, so normal activity in the preceding hour is almost always 0. Attack
   scenarios are dense bursts (about 20 events, seconds apart). **Decision:** these features stay in the model.
   **Limitation:** on this sparse baseline they separate attacks far more easily than they would on production
   telemetry, where normal users generate many events per hour. The floor excludes them.

### Per category (detected at the data-derived high level ≈ 1% FPR)

| Category | Full model AUROC | Full model | Floor |
| --- | --- | --- | --- |
| Credential Misuse | 0.9978 | 97.0% | 42.7% |
| Data Exfiltration | 0.9989 | 97.8% | 39.8% |
| Data Snooping | 0.9994 | 98.9% | 44.0% |
| Privilege Escalation | 0.9987 | 98.3% | 49.4% |
| SQL Injection | 0.9968 | 96.7% | 48.8% |
| Sabotage / Log Tampering | 0.9979 | 97.5% | 48.8% |

All six categories share one generated volume/bytes profile, so these per-category figures mostly reflect that
profile rather than category-specific behaviour.

## Protocol

* **Training:** the earliest 70% of `Normal_Behavior_Learning` by time (42,000 events).
* **Calibration:** the next 15% (9,000 events). Event levels are medium = P95 and high = P99 of these scores.
* **Evaluation:** the last 15% of normal events plus all 2,168 attacks. Labels are read only after freezing.
* **Attribution:** `source_ip → Device_Profiles → employee_id`, exactly as the live collector does it.
* **Personal baselines:** fitted on the training window only.

## Employee risk (decision 3: no counting)

Employee risk is a **time-decayed mean** of the employee's recent event anomaly scores (half-life 24 h). Being a
mean, it does not grow with the number of events.

* **Verified:** duplicating every event changes risk by at most 7e-16 and leaves the ranking identical (`employee_risk_count_invariance`).
* **Level boundaries:** P95 and P99 of the same aggregate, replayed over calibration normals.

| Employee-day evaluation (held-out window) | AUROC |
| --- | --- |
| Full model (count-free rolling risk) | 0.9986 |
| Artifact-free floor | 0.9759 |
| Event count alone (reference only, not used) | 1.0 |

The earlier perfect employee-day score (1.0) came from summing evidence, which grows with event count. With the
count-free aggregate there is no perfect score (`perfect_score_alerts: null`).

At the end of the held-out window, the 13 employees with attacks rank as follows:
* **By peak risk** (the incident view): 1–9, 11, 19, 23 and 30 out of 1,000.
* **By current risk:** lower. Current risk is recency-weighted, so an employee whose latest activity is normal again moves back down.

## Live-path parity (prepares Phase 2)

* **Feature parity:** the collector derives features from raw telemetry (`monitor/brain/telemetry.py`). On normal rows these match the workbook's `Model_Features` to floating-point precision (≤ 4e-14) for all time, byte, latency, schedule and categorical features.
* **`source_events_previous_hour`:** matches on 59,997 of 60,000 normal rows. The 3 exceptions follow an attack burst from the same device: the collector counts all traffic from the IP.
* **Dataset inconsistency:** attack rows in `Model_Features` carry hour/day features that do not match their own timestamps (for example, 19:00 Friday is encoded as 09:30 Thursday). The live path derives time from the timestamp. Attacks replayed through the live path are still detected at 98.3% (high level).

## Acceptance checklist

* **No hand-written attack threshold.** The only fixed numbers are the false-positive budgets (5% / 1%) and the aggregation half-life. Every boundary is a quantile of normal calibration data.
* **No identifier, label or IP in the matrix,** and no port. Enforced by `schema.assert_no_leakage` and covered by tests.
* **No supervised model.**
* **AUROC ≥ 0.98:** met by the full model (0.9983). The floor (0.9736) is reported next to it.
