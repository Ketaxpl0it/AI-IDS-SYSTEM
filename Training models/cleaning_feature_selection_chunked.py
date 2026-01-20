import json
import logging
from typing import List

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
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

CSV_PATH = "CICIDS2017_merged.csv"
OUTPUT_CSV = "ids_dataset.csv"
FEATURE_FILE = "selected_features.json"

TOP_K_FEATURES = 20
RANDOM_STATE = 42

CHUNK_SIZE = 200_000
MAX_SAMPLES_PER_CLASS = 120_000   # total ~240k rows

LEAKAGE_COLUMNS = ["Flow ID", "Source IP", "Destination IP", "Timestamp"]


# ----------------------------
# Functions
# ----------------------------

def collect_samples() -> pd.DataFrame:
    logging.info("Collecting balanced samples from large dataset...")

    benign_frames = []
    attack_frames = []

    for chunk in pd.read_csv(CSV_PATH, chunksize=CHUNK_SIZE):
        chunk.columns = [c.strip() for c in chunk.columns]

        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        chunk.dropna(inplace=True)

        benign = chunk[chunk["Label"] == "BENIGN"]
        attack = chunk[chunk["Label"] != "BENIGN"]

        if len(benign_frames) * CHUNK_SIZE < MAX_SAMPLES_PER_CLASS:
            benign_frames.append(benign)

        if len(attack_frames) * CHUNK_SIZE < MAX_SAMPLES_PER_CLASS:
            attack_frames.append(attack)

        if (
            sum(len(x) for x in benign_frames) >= MAX_SAMPLES_PER_CLASS
            and sum(len(x) for x in attack_frames) >= MAX_SAMPLES_PER_CLASS
        ):
            break

    df = pd.concat(benign_frames + attack_frames, ignore_index=True)
    logging.info("Collected sample shape: %s", df.shape)

    return df


def remove_leakage(df: pd.DataFrame) -> pd.DataFrame:
    removed = []
    for col in LEAKAGE_COLUMNS:
        if col in df.columns:
            df.drop(columns=col, inplace=True)
            removed.append(col)

    if removed:
        logging.info("Removed leakage columns: %s", removed)

    return df


def encode_labels(df: pd.DataFrame) -> pd.DataFrame:
    df["Label"] = df["Label"].apply(lambda x: 0 if str(x).upper() == "BENIGN" else 1)
    return df


def select_features_rf(X: pd.DataFrame, y: pd.Series, k: int) -> List[str]:
    logging.info("Running Random Forest feature ranking...")

    rf = RandomForestClassifier(
        n_estimators=120,
        n_jobs=-1,
        random_state=RANDOM_STATE,
        class_weight="balanced"
    )

    rf.fit(X, y)

    ranked = pd.Series(rf.feature_importances_, index=X.columns).sort_values(ascending=False)

    logging.info("Top %d Features:", k)
    for i, (f, v) in enumerate(ranked.head(k).items(), 1):
        logging.info("%d. %s (%.6f)", i, f, v)

    return list(ranked.head(k).index)


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    df = collect_samples()
    df = remove_leakage(df)
    df = encode_labels(df)

    X = df.drop(columns=["Label"])
    y = df["Label"]

    X_train, _, y_train, _ = train_test_split(
        X, y, test_size=0.3, stratify=y, random_state=RANDOM_STATE
    )

    selected_features = select_features_rf(X_train, y_train, TOP_K_FEATURES)

    final_df = df[selected_features + ["Label"]]

    final_df.to_csv(OUTPUT_CSV, index=False)
    logging.info("Saved Phase 1 dataset to %s", OUTPUT_CSV)

    with open(FEATURE_FILE, "w") as f:
        json.dump(selected_features, f, indent=2)

    logging.info("Saved feature schema to %s", FEATURE_FILE)


if __name__ == "__main__":
    main()
