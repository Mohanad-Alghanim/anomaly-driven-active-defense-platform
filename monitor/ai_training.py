"""Train an interpretable ML model on the isolated synthetic AI_READY dataset."""

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier, export_text


ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "data" / "datasets" / "Anomaly_Defense_Team_Dataset_AI_READY.xlsx"
OUTPUT = ROOT / "models" / "ai_engine"

FEATURES = [
    "failed_auth_count_60s",
    "distinct_ports_60s",
    "requests_10s",
    "sql_pattern_match",
    "file_hash_changed",
    "capability_denied",
]

MODEL_CONFIG = {
    "max_depth": 6,
    "min_samples_leaf": 2,
    "class_weight": "balanced",
    "random_state": 42,
}


def main():
    if not DATASET.is_file():
        raise FileNotFoundError(f"Dataset not found: {DATASET}")

    df = pd.read_excel(DATASET, sheet_name="Raw_Events")

    required = FEATURES + ["attack_category", "session_id", "is_synthetic"]
    missing = [column for column in required if column not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    if not df["is_synthetic"].eq(1).all():
        raise ValueError("Expected a fully synthetic dataset. Training stopped.")

    if df[FEATURES].isna().any().any():
        raise ValueError("Missing feature values found. Training stopped.")

    X = df[FEATURES].apply(pd.to_numeric, errors="raise")
    y = df["attack_category"].astype(str)
    groups = df["session_id"].astype(str)

    if groups.nunique() < 4:
        raise ValueError("Not enough independent sessions for grouped validation.")

    splitter = StratifiedGroupKFold(
        n_splits=4,
        shuffle=True,
        random_state=42,
    )

    oof_true = []
    oof_pred = []
    fold_results = []

    for fold, (train_idx, test_idx) in enumerate(
        splitter.split(X, y, groups), start=1
    ):
        train_groups = set(groups.iloc[train_idx])
        test_groups = set(groups.iloc[test_idx])

        if not train_groups.isdisjoint(test_groups):
            raise RuntimeError("Session leakage detected. Training stopped.")

        model = DecisionTreeClassifier(**MODEL_CONFIG)
        model.fit(X.iloc[train_idx], y.iloc[train_idx])
        predictions = model.predict(X.iloc[test_idx])

        oof_true.extend(y.iloc[test_idx].tolist())
        oof_pred.extend(predictions.tolist())

        fold_results.append({
            "fold": fold,
            "train_records": len(train_idx),
            "test_records": len(test_idx),
            "train_sessions": len(train_groups),
            "test_sessions": len(test_groups),
            "accuracy": accuracy_score(y.iloc[test_idx], predictions),
            "macro_f1": f1_score(
                y.iloc[test_idx],
                predictions,
                average="macro",
                zero_division=0,
            ),
        })

    report = classification_report(
        oof_true,
        oof_pred,
        output_dict=True,
        zero_division=0,
    )

    final_model = DecisionTreeClassifier(**MODEL_CONFIG)
    final_model.fit(X, y)

    OUTPUT.mkdir(parents=True, exist_ok=True)

    joblib.dump(final_model, OUTPUT / "decision_tree.joblib", compress=3)

    metrics = {
        "dataset": DATASET.name,
        "dataset_type": "synthetic_only",
        "records": len(df),
        "sessions": int(groups.nunique()),
        "features": FEATURES,
        "model": "DecisionTreeClassifier",
        "model_config": MODEL_CONFIG,
        "validation": "4-fold StratifiedGroupKFold by session_id",
        "out_of_fold_accuracy": accuracy_score(oof_true, oof_pred),
        "out_of_fold_macro_f1": f1_score(
            oof_true, oof_pred, average="macro", zero_division=0
        ),
        "folds": fold_results,
        "classification_report": report,
        "confusion_matrix": confusion_matrix(
            oof_true, oof_pred, labels=final_model.classes_
        ).tolist(),
        "class_order": final_model.classes_.tolist(),
        "feature_importance": dict(zip(
            FEATURES,
            final_model.feature_importances_.tolist(),
        )),
        "tree_depth": final_model.get_depth(),
        "tree_leaves": final_model.get_n_leaves(),
        "decision_rules": export_text(
            final_model,
            feature_names=FEATURES,
            decimals=3,
        ),
        "limitations": [
            "Training and validation data are synthetic.",
            "Perfect synthetic validation does not establish real-world detection accuracy.",
            "Rare attack classes have only eight independent sessions each.",
            "The model is an advisory classifier, not proof of an attack.",
        ],
    }

    with (OUTPUT / "metrics.json").open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2, ensure_ascii=False, default=lambda value: value.item() if hasattr(value, "item") else str(value))

    print("AI MODEL TRAINED AND SAVED")
    print("Model:", OUTPUT / "decision_tree.joblib")
    print("Metrics:", OUTPUT / "metrics.json")
    print("Records:", len(df))
    print("Sessions:", groups.nunique())
    print("Out-of-fold accuracy:", round(metrics["out_of_fold_accuracy"], 4))
    print("Out-of-fold macro F1:", round(metrics["out_of_fold_macro_f1"], 4))
    print("Tree depth:", final_model.get_depth())
    print("Tree leaves:", final_model.get_n_leaves())
    print("\nDecision rules:\n")
    print(metrics["decision_rules"])


if __name__ == "__main__":
    main()
