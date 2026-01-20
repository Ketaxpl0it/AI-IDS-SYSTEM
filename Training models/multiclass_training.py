import pandas as pd
import numpy as np
import json
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

DATA = "CICIDS2017_merged.csv"

print("[*] Loading dataset...")
df = pd.read_csv(DATA)

# ---------------------------
# CLEANING
# ---------------------------
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# ---------------------------
# ATTACK MAPPING
# ---------------------------
def map_label(lbl):
    l = lbl.lower()

    if "benign" in l:
        return "Benign"
    if "ddos" in l:
        return "DDoS"
    if "dos" in l:
        return "DoS"
    if "portscan" in l:
        return "PortScan"
    if "patator" in l or "brute" in l:
        return "BruteForce"
    if "xss" in l or "sql" in l:
        return "WebAttack"
    if "bot" in l:
        return "Botnet"
    if "infiltration" in l:
        return "Infiltration"
    if "heartbleed" in l:
        return "Heartbleed"
    return "Other"

df["AttackType"] = df["Label"].apply(map_label)

print("\n[+] Attack Type Distribution:")
print(df["AttackType"].value_counts())

# ---------------------------
# FEATURES
# ---------------------------
with open("selected_features.json") as f:
    FEATURES = json.load(f)

X = df[FEATURES]
y = df["AttackType"]

# ---------------------------
# ENCODE LABELS
# ---------------------------
le = LabelEncoder()
y_enc = le.fit_transform(y)

# ---------------------------
# SPLIT
# ---------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc,
    test_size=0.2,
    stratify=y_enc,
    random_state=42
)

# ---------------------------
# MODEL
# ---------------------------
print("\n[*] Training multi-class IDS model...")
model = RandomForestClassifier(
    n_estimators=250,
    max_depth=20,
    n_jobs=-1,
    random_state=42
)

model.fit(X_train, y_train)

# ---------------------------
# EVALUATION
# ---------------------------
y_pred = model.predict(X_test)

print("\n[+] Classification Report:\n")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# ---------------------------
# SAVE
# ---------------------------
joblib.dump(model, "ids_multiclass_model.pkl")
joblib.dump(le, "attack_label_encoder.pkl")

print("\n[+] Saved:")
print("    ids_multiclass_model.pkl")
print("    attack_label_encoder.pkl")
