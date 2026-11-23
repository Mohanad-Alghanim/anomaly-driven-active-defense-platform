# Development of an Anomaly-Driven Active Defense Platform Against Unauthorized Access and Credential Attacks

**Academic report**

## Abstract

This report describes a local platform that detects anomalous activity inside an organisation's network and
responds to it. Telemetry is collected continuously, attributed to employees through a device directory, and scored
by an Isolation Forest trained only on normal behaviour. The model uses 18 features describing time, volume and
each employee's deviation from their own baseline. Event scores are aggregated into a time-decayed employee risk
whose medium and high levels are the 95th and 99th percentiles of normal risk. A dashboard ranks employees, explains
each risk in terms of the employee's own behaviour, and applies a reversible, audited response when the high level is
reached. The application is insider-threat detection. On a synthetic dataset of 1,000 employees, 60,000 normal
events and 2,168 attack events in six categories, the model reaches AUROC 0.9983, AUPRC 0.9948 and 97.7% detection
at a realised false-positive rate of 1.14%. Without the two burst-volume features, the corresponding figures are
AUROC 0.9736, AUPRC 0.8833 and 45.6% detection.

## 1. Introduction

Insider activity is carried out with valid credentials, from known devices, against services the organisation
operates. Individual events therefore resemble legitimate work, and the relevant question is whether an event
departs from what a particular employee normally does. Monitoring based on known patterns does not express this
departure, and results reported per log line do not give the analyst a view per person.

The platform described here takes an unsupervised approach. It learns normal behaviour at two levels, across the
organisation and per employee, and measures every new event against it. The measurement is aggregated per employee,
explained with reference to that employee's baseline, and connected to a bounded response.

The objectives are:

1. to score every event as a deviation from normal behaviour without using attack labels for fitting;
2. to derive risk levels from the distribution of normal behaviour rather than from fixed values;
3. to aggregate event scores into an employee risk that does not increase with the number of events;
4. to explain each risk in terms an analyst can verify; and
5. to apply a response that is triggered by the risk level, confined to a lab environment, reversible and audited.

## 2. Dataset

### 2.1 Composition

The dataset is the synthetic workbook `Behavioral_Intelligence_Dataset_INTERNAL_ATTACKS_6_CLEANED.xlsx`.

| Item | Value |
| --- | --- |
| Employees | 1,000 in 12 departments (83 or 84 per department) |
| Devices | 1,733: 364 employees with one device, 539 with two, 97 with three |
| Device types | Mobile device 371, Windows desktop 348, Linux workstation 347, Windows laptop 339, MacBook 328 |
| Services | 8: Active Directory (389/TCP), DNS (53/UDP), File Server (445/TCP), Internal Web (443/TCP), Database (5432/TCP), SIEM (8088/TCP), SSH Gateway (22/TCP), ERP (8443/TCP) |
| Normal events | 60,000 (60 per employee) |
| Attack events | 2,168 in 114 sessions |
| Time span | 3 August to 23 November 2026, local time zone Asia/Riyadh |

| Attack category | Events | Sessions |
| --- | --- | --- |
| Credential Misuse | 361 | 19 |
| Data Exfiltration | 362 | 19 |
| Data Snooping | 361 | 19 |
| Privilege Escalation | 362 | 19 |
| SQL Injection | 361 | 19 |
| Sabotage / Log Tampering | 361 | 19 |

The workbook contains, among others, the sheets `Organizational_Entities` (employees, schedules), `Device_Profiles`
(device to employee and source IP), `Server_Profiles`, `Normal_Behavior_Learning` (normal events), `Model_Features`
and `Ground_Truth_Evaluation` (labels). The platform's directory (`models/ai_engine/directory.json`) is exported from
the profile sheets and contains no labels.

### 2.2 Data preparation

* **Attribution.** Each event is attributed as `source_ip -> Device_Profiles -> employee_id`, the same path the live
  collector uses. Identifiers are used for attribution and baselines only and never enter the model matrix.
* **Destination port.** In normal events, the destination port is independent of the service (ports 53, 443, 445,
  1194 and 5432 occur for every service), whereas attack events use each service's standard port, and ports 22, 389,
  8088 and 8443 do not occur in normal traffic. The port therefore reflects how the data were generated rather than
  behaviour, and it was excluded from the model. It is still stored and displayed.
* **Personal baselines.** The workbook's `Employee_Behavior_Baselines` sheet is computed over all 60,000 normal
  events, including the evaluation period. Baselines were therefore recomputed from the training window only.

### 2.3 Split

| Split | Content | Events |
| --- | --- | --- |
| Training | Earliest 70% of normal events by time (before 22 October 2026, 07:44 UTC) | 42,000 normal |
| Calibration | Next 15% of normal events | 9,000 normal |
| Evaluation | Remaining normal events (from 4 November 2026, 11:10 UTC) and all attack events | 9,000 normal and 2,168 attack |

The split is chronological, so no evaluation event precedes the training period. Labels from
`Ground_Truth_Evaluation` are read only after the model and its boundaries are fixed.

## 3. Methodology

### 3.1 Features

The model uses 18 features in three groups of six.

**Temporal.** `hour_sin` and `hour_cos` encode local time of day on a circle; `day_of_week_sin` and
`day_of_week_cos` encode the weekday; `is_weekend_observed` flags weekend days of the organisation (Friday and
Saturday); `within_assumed_work_hours` indicates whether the event falls inside the employee's scheduled hours.

**Volume.** `bytes_in_log1p`, `bytes_out_log1p` and `response_time_ms_log1p` are log-transformed transfer sizes and
latency; `source_events_previous_hour` counts events from the same device in the preceding hour; `protocol` and
`destination_service` are the categorical access context of the event.

**Personal deviation.** These features compare the event with the employee's own baseline from the training window:
`emp_bytes_in_z`, `emp_bytes_out_z` and `emp_response_time_z` are z-scores of the log-scaled volume and latency;
`emp_activity_z` is the z-score of the previous-hour activity; `emp_hour_deviation` is the circular distance between
the event's hour and the employee's usual hour, divided by the employee's hour spread; `emp_service_rarity` is the
negative log of the employee's baseline share of the accessed service, with a smoothed value for services never used.

A leakage guard (`monitor/brain/schema.py`) rejects any identifier, label, IP address or port in the model matrix.

### 3.2 Model

The model is a scikit-learn 1.9.1 pipeline. Numeric features are median-imputed and standardised; the two
categorical features are imputed with the most frequent value and one-hot encoded, with unseen categories ignored.
An Isolation Forest with 300 trees (`max_samples="auto"`, `random_state=42`) is fitted on the 42,000 training
events. The anomaly score is the negated `score_samples` output, so higher values are more anomalous. No supervised
estimator is used, and labels are not available to the training code until the model is fixed.

### 3.3 Event levels

Event levels are quantiles of the scores of the 9,000 calibration events, which the model did not see during
fitting. With a 5% false-positive budget for medium and 1% for high, the boundaries are:

| Level | Quantile of calibration scores | Event score boundary |
| --- | --- | --- |
| Medium | 95th percentile | 0.5327 |
| High | 99th percentile | 0.5658 |

The only fixed values in the method are these two budgets and the risk half-life below. All boundaries are
derived from normal data.

### 3.4 Employee risk

Employee risk is the time-decayed mean of the employee's event scores, with each score weighted by
`0.5 ^ (age / 24 h)`. As a mean, it does not increase with the number of events: duplicating every event changes
risk by at most 7×10⁻¹⁶ and leaves the ranking identical. The employee level boundaries are the 95th and 99th
percentiles of the same aggregate replayed over calibration normals: medium 0.5023 and high 0.5348.

Two views of risk are reported. **Current risk** is the value at the latest event and falls back when recent activity
is normal. **Peak risk** is the highest value reached within the selected window, which keeps an incident visible
after it ends. The dashboard ranks by peak risk.

### 3.5 Explanation

For an employee, the explanation identifies the event that contributes most to the current risk, using
`weight × (score − median normal score)`. Recent routine events therefore do not hide an earlier deviation that still
determines the risk. For that event, the deviations from the employee's baseline are ranked by magnitude and stated in
plain language, for example the bytes sent compared with the employee's typical transfer, the number of standard
deviations, the event's local time against the employee's usual hour, or the employee's prior use of the service. The
source IP of that event, with the device hostname and type, is shown alongside.

## 4. Platform Implementation

### 4.1 Architecture

```
  Telemetry sources -> [1] Collection -> [2] Scoring -> [3] Risk aggregation -> [4] Presentation -> [5] Response
```

1. **Collection** (`monitor/worker.py`, `collectors.py`, `journal.py`, `adapters.py`). A single background process
   reads JSONL behavioural telemetry, HTTP access logs, netfilter logs, the systemd Journal and watched files in bounded
   increments every 2 seconds. Cursors, offsets and file hashes are persisted after events are stored and scored, so
   a crash leads to replay rather than loss. Events from unknown sources are stored and scored but not ranked.
2. **Scoring** (`monitor/core.py`, `monitor/brain/`). Features are derived from raw telemetry by the same code used to
   validate against the dataset, then scored by the frozen model.
3. **Risk aggregation** (`monitor/brain/risk.py`, `monitor/views.py`). Employee risk and peak risk are maintained per
   employee.
4. **Presentation** (`app.py`). A Streamlit dashboard on `127.0.0.1:8501` shows the ranking, the explanation, event
   history and charts, and refreshes every 3 seconds.
5. **Response** (`monitor/response.py`). Responses are applied to the loopback lab through
   `runtime/lab/enforcement.json` and recorded in SQLite.

Storage is SQLite in WAL mode with a single writer, deterministic event identities and capacity limits (200,000 events,
about 256 MiB) at which collection pauses rather than deleting data. The collector, dashboard and lab run as systemd
user services on Kali Linux 2026.3 with Python 3.14.10.

### 4.2 Live-path consistency

Features computed by the collector from raw telemetry were compared with the workbook's `Model_Features` for the
normal events. The maximum absolute difference is at most 4×10⁻¹⁴ for all time, volume, latency, schedule and
categorical features. `source_events_previous_hour` matches on 59,997 of 60,000 normal events; the three differences
follow an attack burst from the same device, which the collector counts as traffic from that IP. In `Model_Features`,
the attack rows carry hour and weekday values that do not match their own timestamps (for example, 19:00 on a Friday
encoded as 09:30 on a Thursday); the collector derives time from the timestamp. Attack events replayed through the
collector path reach AUROC 0.9986 and 98.3% detection at the high level.

### 4.3 Active response

A response is proposed when an employee's peak risk reaches the high employee boundary (0.5348). The medium level does
not trigger a response. Three modes are available: automatic (applied by the collector), manual (applied after analyst
approval; the default) and disabled (no new responses). Two actions are applied:

* **block_ip** adds the source IP of the event weighing most on the employee's risk to the enforcement list. The lab
  target refuses requests from that address with HTTP 403, and the collector stores further telemetry from it with
  status `BLOCKED`, without raising the employee's risk.
* **end_session** marks the employee's lab session as ended.

Each response can be reverted from the dashboard; a revert lifts only the enforcement that no other active response
requires. In automatic mode, a reverted response is not re-applied unless the employee's peak risk rises above the
peak already handled. Every response, revert and mode change is written to an audit table with time and actor.

## 5. Evaluation

### 5.1 Event-level results

All attack events against the 9,000 held-out normal events (11,168 events; attack prevalence 19.4%). Detection is
the share of attack events at or above the level boundary.

| Metric | Value | 95% confidence interval |
| --- | --- | --- |
| AUROC | 0.9983 | 0.9974 – 0.9991 |
| AUPRC | 0.9948 | 0.9923 – 0.9970 |
| Detection at the high level (realised FPR 1.14%) | 97.7% | 96.7% – 98.6% |
| Precision at the high level | 0.954 | – |
| Detection at the medium level (realised FPR 5.26%) | 99.2% | – |
| Precision at the medium level | 0.820 | – |

**Chronological test window.** Restricting attacks to the same period as the held-out normals (9,515 events, 515
attacks, prevalence 5.4%) gives AUROC 0.9984, AUPRC 0.9861, detection 97.7% and precision 0.830 at the high level,
and detection 99.0% and precision 0.519 at the medium level.

### 5.2 Per attack category

| Category | AUROC | AUPRC | Detection at high level | Detection at medium level | Sessions with a high event |
| --- | --- | --- | --- | --- | --- |
| Credential Misuse | 0.9978 | 0.9766 | 97.0% | 98.9% | 19 / 19 |
| Data Exfiltration | 0.9989 | 0.9876 | 97.8% | 99.4% | 19 / 19 |
| Data Snooping | 0.9994 | 0.9926 | 98.9% | 99.7% | 19 / 19 |
| Privilege Escalation | 0.9987 | 0.9821 | 98.3% | 99.4% | 19 / 19 |
| SQL Injection | 0.9968 | 0.9771 | 96.7% | 98.9% | 19 / 19 |
| Sabotage / Log Tampering | 0.9979 | 0.9783 | 97.5% | 98.6% | 19 / 19 |

### 5.3 Feature audit and model variants

Each feature was evaluated alone as a score (univariate AUROC). Six features separate attacks from normal events
almost completely on their own: `emp_activity_z` (0.987), `source_events_previous_hour` (0.985), `bytes_in_log1p`
(0.975), `emp_bytes_in_z` (0.975), `response_time_ms_log1p` (0.969) and `emp_response_time_z` (0.969). The temporal
features range from 0.542 to 0.715, `emp_hour_deviation` is 0.766 and `emp_service_rarity` is 0.621.

The two burst-volume features reflect a property of the dataset: each employee has 60 normal events over the period,
so normal activity in the preceding hour is almost always zero, while attack sessions are dense sequences of about
20 events seconds apart. The model was therefore also evaluated without them.

| Variant | Features | AUROC | AUPRC | Detection at 1% FPR | Realised FPR |
| --- | --- | --- | --- | --- | --- |
| Full model | 18 | 0.9983 | 0.9948 | 97.7% | 1.14% |
| Without burst-volume features | 16 | 0.9736 | 0.8833 | 45.6% | 1.24% |
| Dataset base features only (without port) | 12 | 0.9852 | 0.9283 | 49.5% | 0.73% |

| Category | Detection at 1% FPR, full model | Without burst-volume features | Base features only |
| --- | --- | --- | --- |
| Credential Misuse | 97.0% | 42.7% | 56.0% |
| Data Exfiltration | 97.8% | 39.8% | 43.6% |
| Data Snooping | 98.9% | 44.0% | 46.8% |
| Privilege Escalation | 98.3% | 49.4% | 51.7% |
| SQL Injection | 96.7% | 48.8% | 52.6% |
| Sabotage / Log Tampering | 97.5% | 48.8% | 46.5% |

### 5.4 Employee-level results

Employee-days in the held-out window were scored by the employee risk at the last event of the day (5,986
employee-days, 13 containing attacks, prevalence 0.22%).

| Variant | AUROC | AUPRC | Detection at high level | FPR | Precision |
| --- | --- | --- | --- | --- | --- |
| Full model | 0.9986 | 0.6696 | 13 / 13 (100%) | 1.47% | 0.129 |
| Without burst-volume features | 0.9759 | 0.2293 | 9 / 13 (69.2%) | 1.44% | 0.095 |

The rank correlation between employee risk and event count is 0.04 (Spearman), confirming that the risk does not
follow activity volume. Among 1,000 employees at the end of the held-out window, the 13 employees with attacks are
ranked 1–9, 11, 19, 23 and 30 by peak risk. By current risk they are ranked 1, 2, 3, 91, 108, 256, 268, 280, 552,
555, 623, 766 and 794, because current risk returns towards normal once recent activity is normal again. Six
employees are at the high level by current risk at the end of the window.

### 5.5 Live scenarios

Six scenario scripts reproduce one attack of each category against the running platform. Each impersonates a
directory employee from that employee's device IP, writes telemetry to the lab inbox, and where possible performs a
real action against the loopback lab (an SQL injection that returns both rows of the lab catalog, and a modification
of a watched file). Scenario timestamps are placed on a fixed mid-week workday within the past 7 days, because the
weekday is a model feature; the credential-misuse scenario uses the hour opposite the employee's usual hour. On an
empty live database the collector produced the following ranking, and automatic response blocked the four high-level
employees on the source IPs of their scenario events:

| Rank | Employee | Scenario | Peak risk | Level | Blocked IP |
| --- | --- | --- | --- | --- | --- |
| 1 | EMP0027 | Sabotage / log tampering | 0.627 | High | 10.200.0.56 |
| 2 | EMP0318 | Data exfiltration | 0.625 | High | 10.200.2.55 |
| 3 | EMP0003 | Privilege escalation | 0.576 | High | 10.200.0.13 |
| 4 | EMP0026 | SQL injection | 0.556 | High | 10.200.0.55 |
| 5 | EMP0101 | Credential misuse | 0.519 | Medium | – |
| 6 | EMP0009 | Out-of-role data snooping | 0.508 | Medium | – |

A repeated request from a blocked address was refused by the lab with HTTP 403, and its telemetry was stored as
`BLOCKED` without raising the employee's risk. Reverting a response from the dashboard removed the block and recorded
the revert in the audit log.

### 5.6 Software verification

The automated suite contains 89 pytest tests covering the leakage guard, normal-only fitting, level derivation,
count-independent risk, explanation, collection and attribution, the collector lifecycle, the lab, the scenarios on
every weekday, response selection and reversal, and the dashboard.

## 6. Discussion

The full model separates attack events from normal events almost completely on this dataset, and every attack session
contains at least one event at the high level. The feature audit shows that a large part of this separation comes from
burst volume and transfer size, which are near-separating on their own. Without the burst-volume features, AUROC
remains 0.9736 but detection at 1% FPR falls to 45.6%, which indicates that the ordering of events remains largely
correct while the margin above the high boundary is smaller. The per-category figures are close to one another
because all six categories share one generated volume profile.

At the employee level, all 13 attacked employee-days reach the high level, with a false-positive rate of 1.47%. With a
prevalence of 0.22%, this corresponds to a precision of 0.129, so most high-level employee-days in the held-out window
are normal. Ranking by peak risk places all 13 attacked employees within the top 30 of 1,000, which reduces the review
effort compared with the full population.

In the live scenarios, the four scenarios that combine two deviations reached the high level, while the two that rely
on a single small deviation (an out-of-role destination at low volume, or an unusual hour) reached the medium level.
This matches the scenario design and the reduced-feature results.

## 7. Limitations

* The data are synthetic; the results do not establish detection performance on real networks.
* The normal baseline is sparse (60 events per employee), so burst-volume features separate attacks more easily than
  they would on production telemetry.
* All attack categories share one generated volume profile.
* Attack rows in the workbook's `Model_Features` sheet carry time features inconsistent with their timestamps; the
  platform derives time from timestamps.
* Anomaly scores measure deviation from learned normal behaviour and do not establish intent.
* Responses are confined to the loopback lab and the collector.
* The platform runs on a single host with one SQLite database.

## 8. Future Work

* Evaluation on real enterprise telemetry with denser normal activity.
* Scheduled retraining and monitoring of drift in normal behaviour.
* Sequence-aware features that use the order and timing of events within a session.
* Integration of responses with host firewalls or network access control under an approval workflow.
* Multi-host collection with a central store.

## 9. Conclusion

The platform implements unsupervised anomaly detection from collection to response. An Isolation Forest trained on
normal behaviour, with features describing each employee's deviation from their own baseline, scores every event;
risk levels are percentiles of normal behaviour; employee risk is independent of event counts; each risk is explained
with reference to the employee's baseline; and responses are triggered by the risk level, confined to the lab,
reversible and audited. On the synthetic dataset the model reaches AUROC 0.9983 and 97.7% detection at a 1.14%
false-positive rate, and 45.6% detection without the burst-volume features.

## Reproducibility

* Retraining: `.venv/bin/python -m monitor.brain.train` (requires the workbook in `data/`; deterministic with
  `random_state=42`).
* All figures in sections 5.1–5.4 are stored in `models/ai_engine/metrics.json`.
* Environment: Python 3.14.10, NumPy 2.5.5, pandas 2.3.3, scikit-learn 1.9.1, joblib 1.6.0; the full pinned list is in
  `requirements.txt`.
