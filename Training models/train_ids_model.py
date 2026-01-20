import json
import logging
from typing import Tuple

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split


# ----------------------------
# Logging
# ----------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ----------------------------
# Config
# ----------------------------

DATASET_PATH = "ids_dataset.csv"
FEATURE_FILE = "selected_features.json"

MODEL_FILE = "ids_model.pkl"
META_FILE = "model_metadata.json"

RANDOM_STATE = 42


# ----------------------------
# Helpers
# ----------------------------

def load_data() -> Tuple[pd.DataFrame, pd.Series, list]:
    df = pd.read_csv(DATASET_PATH)

    with open(FEATURE_FILE) as f:
        features = json.load(f)

    X = df[features]
    y = df["Label"]

    logging.info("Dataset loaded: %s", df.shape)
    logging.info("Attack ratio: %.2f%%", (y.sum() / len(y)) * 100)

    return X, y, features


def print_soc_metrics(y_true, y_pred) -> None:
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    recall = tp / (tp + fn)
    fpr = fp / (fp + tn)

    logging.info("Confusion Matrix:\n%s", cm)
    logging.info("Recall (Attack Detection Rate): %.4f", recall)
    logging.info("False Positive Rate: %.4f", fpr)

    print("\nClassification Report:\n")
    print(classification_report(y_true, y_pred, digits=4))


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    X, y, features = load_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.25,
        stratify=y,
        random_state=RANDOM_STATE
    )

    logging.info("Applying SMOTE to handle class imbalance...")

    smote = SMOTE(random_state=RANDOM_STATE)
    X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)

    logging.info("Training samples after SMOTE: %s", X_train_bal.shape)

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        n_jobs=-1,
        random_state=RANDOM_STATE,
        class_weight="balanced_subsample"
    )

    logging.info("Training Random Forest IDS model...")
    model.fit(X_train_bal, y_train_bal)

    logging.info("Evaluating on test set...")
    y_pred = model.predict(X_test)

    print_soc_metrics(y_test, y_pred)

    joblib.dump(model, MODEL_FILE)
    logging.info("Saved trained model to %s", MODEL_FILE)

    metadata = {
        "features": features,
        "model": "RandomForestClassifier",
        "positive_label": "ATTACK",
        "threshold": 0.5
    }

    with open(META_FILE, "w") as f:
        json.dump(metadata, f, indent=2)

    logging.info("Saved model metadata to %s", META_FILE)


if __name__ == "__main__":
    main()
