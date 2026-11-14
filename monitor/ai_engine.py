"""Read-only AI analysis for alerts in the Active Defense Platform."""

from functools import lru_cache
from pathlib import Path

import joblib

from .core import CATEGORIES, PRIV, SQL


ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT / "models" / "ai_engine" / "decision_tree.joblib"

FEATURES = [
    "failed_auth_count_60s",
    "distinct_ports_60s",
    "requests_10s",
    "sql_pattern_match",
    "file_hash_changed",
    "capability_denied",
]

LABEL_MAP = {
    "DoS Indicator": "Denial of Service (DoS)",
    "Port Scanning": "Port Scanning",
    "SQL Injection": "SQL Injection",
    "SSH Brute Force": "SSH Brute Force",
    "Suspicious Privilege Escalation": "Suspicious Privilege Escalation",
    "Unauthorized File Modification": "Unauthorized File Modification",
    "none": "No matching attack class",
}


@lru_cache(maxsize=1)
def load_model():
    """Load the locally trained model once per application process."""
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"AI model not found: {MODEL_PATH}")

    model = joblib.load(MODEL_PATH)

    if list(model.feature_names_in_) != FEATURES:
        raise ValueError("Model feature schema does not match AI engine.")

    return model


def _event_for_alert(engine, alert):
    event_id = alert.get("event_id")
    if not event_id:
        raise ValueError("Alert has no event_id.")

    return engine.db.execute(
        "SELECT * FROM events WHERE id = ?",
        (event_id,),
    ).fetchone()


def _extract_features(engine, event):
    """Extract observed behavioral features from stored events."""
    event = dict(event)
    ts = float(event["ts"])
    ip = event.get("ip")
    kind = event.get("kind")
    message = event.get("message") or ""

    evidence = []
    features = {}

    # Network windows require an observed source IP.
    # File and privilege events do not use network-window features
    # in the synthetic training schema; encode them as not applicable.
    network_context_required = kind in ("ssh_failed", "connection", "http")
    ip_context_available = bool(ip) or not network_context_required

    if ip:
        failed = engine.db.execute(
            """SELECT COUNT(*) FROM events
               WHERE kind = 'ssh_failed' AND ip = ?
               AND ts BETWEEN ? AND ?""",
            (ip, ts - 60, ts),
        ).fetchone()[0]

        ports = engine.db.execute(
            """SELECT COUNT(DISTINCT port) FROM events
               WHERE kind = 'connection' AND ip = ?
               AND ts BETWEEN ? AND ?""",
            (ip, ts - 60, ts),
        ).fetchone()[0]

        requests = engine.db.execute(
            """SELECT COUNT(*) FROM events
               WHERE kind = 'http' AND ip = ?
               AND ts BETWEEN ? AND ?""",
            (ip, ts - 10, ts),
        ).fetchone()[0]

        features["failed_auth_count_60s"] = int(failed)
        features["distinct_ports_60s"] = int(ports)
        features["requests_10s"] = int(requests)

        evidence.extend([
            {
                "feature": "failed_auth_count_60s",
                "value": int(failed),
                "window_seconds": 60,
                "source": "events table",
            },
            {
                "feature": "distinct_ports_60s",
                "value": int(ports),
                "window_seconds": 60,
                "source": "events table",
            },
            {
                "feature": "requests_10s",
                "value": int(requests),
                "window_seconds": 10,
                "source": "events table",
            },
        ])
    elif not network_context_required:
        for name in (
            "failed_auth_count_60s",
            "distinct_ports_60s",
            "requests_10s",
        ):
            features[name] = 0

        evidence.append({
            "feature_group": "network_behavior",
            "value": "not_applicable",
            "reason": f"Event kind is {kind}; network-window features are not applicable.",
        })

    sql_match = bool(kind == "http" and SQL.search(message))
    file_changed = bool(kind == "file" and not event.get("authorized"))
    capability_denied = bool(kind == "privilege" and PRIV.search(message))

    features["sql_pattern_match"] = int(sql_match)
    features["file_hash_changed"] = int(file_changed)
    features["capability_denied"] = int(capability_denied)

    evidence.extend([
        {
            "feature": "sql_pattern_match",
            "value": int(sql_match),
            "source": "original SQL detection pattern",
        },
        {
            "feature": "file_hash_changed",
            "value": int(file_changed),
            "source": "file event authorization status",
        },
        {
            "feature": "capability_denied",
            "value": int(capability_denied),
            "source": "original privilege detection pattern",
        },
    ])

    return features, evidence, ip_context_available


def _decision_path(model, features):
    """Explain the actual decision-tree branches traversed."""
    import pandas as pd

    frame = pd.DataFrame([[features[name] for name in FEATURES]], columns=FEATURES)
    tree = model.tree_
    path = model.decision_path(frame).indices
    explanations = []

    for node_id in path:
        feature_index = tree.feature[node_id]

        if feature_index < 0:
            continue

        name = FEATURES[feature_index]
        threshold = float(tree.threshold[node_id])
        value = float(features[name])
        operator = "<=" if value <= threshold else ">"

        explanations.append({
            "feature": name,
            "observed_value": value,
            "condition": f"{name} {operator} {threshold:.3f}",
            "branch": "left" if value <= threshold else "right",
        })

    return explanations


def _build_incident_explanation(report):
    """Build an evidence-grounded English explanation for an alert."""
    attack = report.get("attack")
    features = report.get("features", {})
    event = report.get("event", {})
    severity = report.get("severity") or "Unspecified"
    ip = event.get("ip")
    action = report.get("recommended_action") or "Review the event and verify whether it was authorized."

    source_text = f" Source IP: {ip}." if ip else ""

    explanations = {
        "SSH Brute Force": (
            f"The platform detected repeated failed SSH authentication attempts. "
            f"It recorded {features.get('failed_auth_count_60s', 'an unavailable number')} "
            f"failed attempts within the 60-second observation window.{source_text}",
            "The event matched the platform's SSH brute-force threshold. "
            "The observed failed-authentication count supports the original alert.",
        ),
        "Port Scanning": (
            f"The platform detected connection attempts involving "
            f"{features.get('distinct_ports_60s', 'an unavailable number')} distinct destination ports "
            f"within the 60-second observation window.{source_text}",
            "The observed number of distinct ports met the configured port-scanning detection threshold.",
        ),
        "SQL Injection": (
            "The platform detected an HTTP request containing a pattern associated "
            "with a possible SQL injection attempt.",
            "The request matched one of the predefined SQL detection patterns. "
            "This is an indicator requiring investigation, not proof that a database was compromised.",
        ),
        "Denial of Service (DoS)": (
            f"The platform detected a high volume of HTTP requests. "
            f"It counted {features.get('requests_10s', 'an unavailable number')} requests "
            f"within the 10-second observation window.{source_text}",
            "The observed request count met the configured HTTP traffic threshold. "
            "The alert indicates possible service pressure; actual service impact has not been established.",
        ),
        "Unauthorized File Modification": (
            "The platform detected a file modification without a matching authorization.",
            "The file event was marked as unauthorized. The file authorization status "
            "triggered the original file-integrity detection rule.",
        ),
        "Suspicious Privilege Escalation": (
            "The platform detected a privilege-related event matching a predefined suspicious-operation pattern.",
            "The capability-denied indicator was observed and the event matched the original "
            "privilege detection pattern. This does not establish that elevated privileges were obtained.",
        ),
    }

    summary, reason = explanations.get(
        attack,
        (
            "The platform generated a security alert for an event requiring review.",
            "The available event metadata and original detection rule should be reviewed.",
        ),
    )

    return {
        "what_happened": summary,
        "why_flagged": reason,
        "recommended_response": action,
        "severity": severity,
    }


def analyze_alert(engine, alert):
    """
    Analyze one alert using read-only event access.
    Does not write to live.db or change detection decisions.
    """
    if not isinstance(alert, dict):
        alert = dict(alert)

    event_row = _event_for_alert(engine, alert)
    if event_row is None:
        raise ValueError("The event associated with this alert was not found.")

    event = dict(event_row)
    features, evidence, context_available = _extract_features(engine, event)

    report = {
        "alert_id": alert.get("id"),
        "event_id": alert.get("event_id"),
        "attack": alert.get("attack"),
        "severity": alert.get("severity"),
        "rule": alert.get("rule"),
        "description": alert.get("description"),
        "recommended_action": alert.get("action"),
        "event": {
            "timestamp": event.get("ts"),
            "kind": event.get("kind"),
            "source": event.get("source"),
            "ip": event.get("ip"),
            "message": event.get("message"),
            "authorized": event.get("authorized"),
            "status": event.get("status"),
        },
        "features": features,
        "evidence": evidence,
        "model_status": "NOT RUN",
        "model_prediction": None,
        "model_probability": None,
        "decision_path": [],
        "limitations": [
            "The model was trained on synthetic data only.",
            "Model probabilities are not calibrated real-world confidence.",
            "The original detection rule remains authoritative.",
        ],
    }

    report["incident_explanation"] = _build_incident_explanation(report)

    if not context_available:
        report["limitations"].append(
            "No source IP is available; IP-based behavioral windows cannot be calculated."
        )
        return report

    model = load_model()

    import pandas as pd

    frame = pd.DataFrame(
        [[features[name] for name in FEATURES]],
        columns=FEATURES,
    )

    prediction = str(model.predict(frame)[0])
    probabilities = model.predict_proba(frame)[0]
    class_index = list(model.classes_).index(prediction)

    report["model_status"] = "COMPLETED"
    report["model_prediction"] = LABEL_MAP.get(prediction, prediction)
    report["model_probability"] = float(probabilities[class_index])
    report["decision_path"] = _decision_path(model, features)

    detected = alert.get("attack")
    predicted = report["model_prediction"]

    report["classification_agreement"] = (
        predicted == detected
        or (predicted == "No matching attack class" and detected is None)
    )

    if not report["classification_agreement"]:
        report["limitations"].append(
            "The model prediction differs from the original alert category. "
            "This is a review signal, not permission to override the detection rule."
        )

    return report
