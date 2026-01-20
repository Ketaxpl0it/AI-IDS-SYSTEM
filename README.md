# 🛡️ AI-Based Intrusion Detection System (AI-IDS)

An AI-powered Intrusion Detection System (IDS) that monitors live network traffic, detects cyber attacks using Machine Learning and behavior-based rules, maps attacks to the MITRE ATT&CK framework, stores forensic evidence, and provides a real-time dashboard for monitoring alerts.

---

## 🚀 Features

* ✅ Live packet capture using Scapy
* ✅ Flow-based traffic analysis
* ✅ Multi-class Machine Learning attack classification
* ✅ Detection of:

  * DoS / DDoS
  * Port Scanning
  * Brute Force
  * Botnet behavior
  * Web attacks (from ML model)
* ✅ Behavior-based overrides for:

  * Flood attacks
  * Port scanning
* ✅ MITRE ATT&CK mapping:

  * **T1046** – Network Service Scanning
  * **T1498** – Network Denial of Service
* ✅ Automatic IP blocking (Windows Firewall)
* ✅ Auto-unblock after cooldown period
* ✅ Forensic evidence capture (PCAP per attack)
* ✅ Real-time Streamlit dashboard

---

## 📁 Project Structure

```
AI-IDS-SYSTEM
│
├── ids_engine_live.py            # Live IDS engine
├── ids_dashboard.py              # Streamlit dashboard
│
├── Training models/
│   ├── merge_cicids2017.py
│   ├── cleaning_feature_selection_chunked.py
│   ├── train_ids_model.py
│   ├── multiclass_training.py
│   ├── selected_features.json
│   └── model_metadata.json
│
└── evidence/                     # Auto-generated forensic PCAPs
```

---

## ⚙️ Requirements

```bash
pip install scapy pandas numpy scikit-learn joblib streamlit
```

### Windows Packet Capture

Install **Npcap** and enable:

* ✔ WinPcap API-compatible mode

Run IDS as **Administrator**.

---

## 🧠 Model Training Steps (Very Important)

⚠️ Model `.pkl` files are not included in GitHub because of size limits.
You must train the models locally using CICIDS2017 dataset.

### ✅ Step 1: Download Dataset

Download CICIDS2017 CSV files from:

[https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)

Place all CSV files in a folder, for example:

```
dataset_raw/
```

---

### ✅ Step 2: Merge All CSV Files

```bash
cd "Training models"
python merge_cicids2017.py
```

This creates:

```
CICIDS2017_merged.csv
```

---

### ✅ Step 3: Clean Dataset + Feature Selection

This script works in chunks (low RAM systems supported):

```bash
python cleaning_feature_selection_chunked.py
```

Outputs:

* `ids_dataset.csv` (clean dataset)
* `selected_features.json`

---

### ✅ Step 4: Train Binary IDS Model (Optional)

Binary model = Benign vs Attack

```bash
python train_ids_model.py
```

Outputs:

* `ids_model.pkl`

(Used only if you enable binary detection)

---

### ✅ Step 5: Train Multi-Class IDS Model (Required)

Multi-class model predicts attack type.

```bash
python multiclass_training.py
```

Outputs:

* `ids_multiclass_model.pkl`
* `attack_label_encoder.pkl`

---

### ✅ Step 6: Copy Models to Root Folder

Move these files to project root:

```
ids_multiclass_model.pkl
attack_label_encoder.pkl
selected_features.json
model_metadata.json
```

Final structure:

```
AI-IDS-SYSTEM/
├── ids_engine_live.py
├── ids_dashboard.py
├── ids_multiclass_model.pkl
├── attack_label_encoder.pkl
├── selected_features.json
└── model_metadata.json
```

---

## ▶️ How to Run IDS

### 1️⃣ Start IDS Engine (Admin)

```bash
python ids_engine_live.py
```

---

### 2️⃣ Start Dashboard

```bash
streamlit run ids_dashboard.py
```

Open:

```
http://localhost:8501
```

---

## 🧪 Attack Simulation

### 🔥 DoS Attack

```bash
sudo hping3 -S --flood -p 80 <TARGET_IP>
```

### 🔍 Port Scan

```bash
nmap -sS -T5 -Pn <TARGET_IP>
```

---

## 🔐 Firewall Response

* High severity → IP blocked
* Auto-unblock after cooldown
* Windows Firewall rules added dynamically

---

## 🧾 Forensics

PCAP evidence saved per attack:

```
evidence/<attacker_ip>_<timestamp>/
```

---

## 🎯 MITRE ATT&CK Mapping

| Attack    | ID    | Technique                 |
| --------- | ----- | ------------------------- |
| Port Scan | T1046 | Network Service Scanning  |
| DoS/DDoS  | T1498 | Network Denial of Service |

---

## 👨‍💻 Author

**Neel Tundiya**
Cybersecurity Researcher | VAPT | AI for Security

---

## ⭐ Support

Star ⭐ the repo if you like it and feel free to fork and improve!
