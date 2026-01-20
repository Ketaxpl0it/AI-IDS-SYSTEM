import logging
from pathlib import Path

import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

OUTPUT_FILE = "CICIDS2017_merged.csv"


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.strip() for c in df.columns]
    return df


def main() -> None:
    csv_files = list(Path(".").glob("*.csv"))

    if not csv_files:
        raise RuntimeError("No CSV files found in current directory")

    logging.info("Found %d CSV files", len(csv_files))

    frames = []

    for file in csv_files:
        logging.info("Loading %s", file.name)
        df = pd.read_csv(file)
        df = normalize_columns(df)
        frames.append(df)

    merged_df = pd.concat(frames, ignore_index=True)

    logging.info("Merged dataset shape: %s", merged_df.shape)

    merged_df.to_csv(OUTPUT_FILE, index=False)
    logging.info("Saved merged dataset to %s", OUTPUT_FILE)


if __name__ == "__main__":
    main()
