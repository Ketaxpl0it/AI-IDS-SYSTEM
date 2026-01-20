import json
import time
import os
from collections import defaultdict
#from typing import Tuple
import platform, subprocess
import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, wrpcap, IPv6




attacker_profile = defaultdict(lambda: {
    "PortScan": 0,
    "DoS": 0,
    "BruteForce": 0,
    "Other": 0,
    "last_seen": 0
})
# =========================
# CONFIG
# =========================

MODEL_PATH = "ids_model.pkl"
FEATURE_FILE = "selected_features.json"
ALERT_FILE = "live_alerts.json"

FLOW_TIMEOUT = 15
MIN_PKTS_FOR_RATE = 200

MAX_ALERTS = 300
ML_HIGH = 0.60        # real anomaly
ML_MEDIUM = 0.45     # suspicious

RATE_HIGH = 1500     # DoS
RATE_MEDIUM = 400
packet_count = 0

src_flow_counter = defaultdict(list)   # src_ip -> timestamps
SCAN_FLOW_THRESHOLD = 20
SCAN_WINDOW = 10

src_pps_counter = defaultdict(list)   # src_ip -> [timestamps]
SRC_RATE_WINDOW = 2                  # seconds
SRC_PPS_THRESHOLD = 500              # flood trigger

blocked_ips = {}
BLOCK_DURATION = 120   # seconds (2 minutes)

BASELINE_WINDOW = 200   # last N flows

EVIDENCE_DIR = "evidence"
PCAP_LIMIT = 2000  # packets per incident

GLOBAL_PPS_THRESHOLD = 5000

# =========================
# LOAD MODEL
# =========================

# print("[*] Loading IDS model...")
# model = joblib.load(MODEL_PATH)
print("[*] Loading Multi-Class IDS model...")
model = joblib.load("ids_multiclass_model.pkl")
label_encoder = joblib.load("attack_label_encoder.pkl")

with open(FEATURE_FILE) as f:
    FEATURES = json.load(f)

print("[*] IDS Engine Running...")


# =========================
# ATTACK CAMPAIGN TRACKER
# =========================

ATTACK_CHAIN_WINDOW = 120   # seconds
MIN_STAGES_FOR_CAMPAIGN = 2

attack_history = defaultdict(list)
# =========================
# STATE
# =========================

FlowKey = tuple  # (src, dst, sport, dport, proto)
flows = {}
flow_packets = defaultdict(list)
alerts = []
FLOW_PPS_THRESHOLD = 800
# Cooldown per Attack
recent_attack = {}
ATTACK_COOLDOWN = 30

# RATE Baseline
pps_history = []
MAX_PPS_HISTORY = 300


# Port scan tracking
port_scan_tracker = defaultdict(list)  # src_ip -> [(port, time)]
PORT_SCAN_WINDOW = 10
PORT_SCAN_THRESHOLD = 5


ATTACK_PROFILE_WINDOW = 120   # seconds
ESCALATION_THRESHOLD = 2

attack_timeline = []
MAX_TIMELINE = 500

# ===== Source Behavior Tracking =====

src_packet_times = defaultdict(list)     # src_ip -> [timestamps]
src_ports = defaultdict(set)              # src_ip -> {dst_ports}

SRC_RATE_WINDOW = 2        # seconds
SRC_PPS_THRESHOLD = 400    # hping flood threshold

SCAN_PORT_THRESHOLD = 20   # nmap ports within window
SCAN_WINDOW = 10           # seconds

# =========================
# MITRE ATT&CK MAPPING
# =========================

MITRE_MAP = {
    "PortScan": {
        "tactic": "Reconnaissance",
        "technique": "Network Service Scanning",
        "id": "T1046"
    },
    "BruteForce": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "id": "T1110"
    },
    "DoS": {
        "tactic": "Impact",
        "technique": "Network Denial of Service",
        "id": "T1498"
    },
    "DDoS": {
        "tactic": "Impact",
        "technique": "Network Denial of Service",
        "id": "T1498"
    },
    "Botnet": {
        "tactic": "Command and Control",
        "technique": "Botnet Communication",
        "id": "T1095"
    },
    "Infiltration": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "id": "T1190"
    },
    "WebAttack": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "id": "T1190"
    }
}
# =========================
# HELPERS
# =========================

def new_flow():
    now = time.time()
    return {
        "start": now,
        "last": now,
        "fwd_packets": 0,
        "bwd_packets": 0,
        "fwd_bytes": 0,
        "bwd_bytes": 0,
        "pkt_sizes": []
    }



def build_features(flow: dict) -> dict:
    duration = max(flow["last"] - flow["start"], 1.0)
    total_packets = flow["fwd_packets"] + flow["bwd_packets"]
    total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]
    pkt_sizes = flow["pkt_sizes"] or [0]

    return {
        "Flow Duration": duration * 1e6,
        "Total Fwd Packets": flow["fwd_packets"],
        "Total Backward Packets": flow["bwd_packets"],
        "Total Length of Fwd Packets": flow["fwd_bytes"],
        "Total Length of Bwd Packets": flow["bwd_bytes"],
        "Average Packet Size": np.mean(pkt_sizes),
        "Packet Length Variance": np.var(pkt_sizes),
        "Flow Bytes/s": total_bytes / duration,
        "Flow Packets/s": total_packets / duration,
    }


def save_alert(event):
    alerts.append(event)

    with open(ALERT_FILE, "w") as f:
        json.dump(alerts[-MAX_ALERTS:], f, indent=2)

    print("🚨 ALERT:", event)


def classify_flow(flow, key, scan_ports):
    try:
        feats = build_features(flow)

        row = [feats.get(f, 0) for f in FEATURES]
        X = pd.DataFrame([row], columns=FEATURES)

        pred = model.predict(X)[0]
        attack = label_encoder.inverse_transform([pred])[0]
        probs = model.predict_proba(X)[0]
        confidence = float(np.max(probs))

        pps = feats.get("Flow Packets/s", 0)
        pkt_count = flow["fwd_packets"] + flow["bwd_packets"]

        src_ip = key[0]
        now = time.time()

        # -----------------------------
        # BEHAVIOR OVERRIDES
        # -----------------------------
        src_pps = len(src_pps_counter.get(src_ip, [])) / SRC_RATE_WINDOW

        if scan_ports >= PORT_SCAN_THRESHOLD:
            attack = "PortScan"
            confidence = 1.0

        elif src_pps >= SRC_PPS_THRESHOLD:
            attack = "DoS"
            confidence = 1.0

        elif attack == "Benign":
            return

        # -----------------------------
        # COOLDOWN (SUPPRESS DUPLICATES)
        # -----------------------------
        last = recent_attack.get(src_ip, 0)
        if now - last < ATTACK_COOLDOWN:
            return

        recent_attack[src_ip] = now

        # -----------------------------
        # UPDATE ATTACKER PROFILE
        # -----------------------------
        profile = attacker_profile[src_ip]

        if attack in profile:
            profile[attack] += 1
        else:
            profile["Other"] += 1

        profile["last_seen"] = now

        # -----------------------------
        # MULTI-STAGE CORRELATION
        # -----------------------------
        stage_count = (
            (profile.get("PortScan", 0) > 0) +
            (profile.get("DoS", 0) > 0) +
            (profile.get("BruteForce", 0) > 0)
        )

        if stage_count >= 2:
            severity = "Critical"
            correlated_attack = "Multi-Stage Attack"

        elif attack in ["DoS", "DDoS", "Botnet", "BruteForce"]:
            severity = "High"
            correlated_attack = attack

        else:
            severity = "Medium"
            correlated_attack = attack

        # -----------------------------
        # MITRE MAP
        # -----------------------------
        mitre = MITRE_MAP.get(correlated_attack, {
            "tactic": "Unknown",
            "technique": "Unknown",
            "id": "N/A"
        })

        ts = time.strftime("%Y-%m-%d %H:%M:%S")

        event = {
            "DateTime": ts,
            "Source": src_ip,
            "Destination": key[1],
            "SrcPort": key[2],
            "DstPort": key[3],
            "Protocol": key[4],
            "Attack_Type": correlated_attack,
            "Stage": attack,
            "Severity": severity,
            "Confidence": round(confidence, 3),
            "Pkts": pkt_count,
            "Pkts_per_sec": int(pps),
            "MITRE_Tactic": mitre["tactic"],
            "MITRE_Technique": mitre["technique"],
            "MITRE_ID": mitre["id"]
        }

        print("🚨 ALERT:", event)
        save_alert(event)
        save_evidence(flow, key, event)

        attack_timeline.append(event)
        if len(attack_timeline) > MAX_TIMELINE:
            attack_timeline.pop(0)

        # -----------------------------
        # AUTO BLOCK
        # -----------------------------
        if severity in ["High", "Critical"]:
            block_ip(src_ip)

    except Exception as e:
        print("[CLASSIFY ERROR]", e)








def handle_packet(pkt):
    global packet_count
    packet_count += 1

    if packet_count % 50 == 0:
        print(f"[+] Packets seen: {packet_count}")

    # ---- IP Layer ----
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if not ip:
        return

    src = ip.src
    dst = ip.dst

    now = time.time()
    src_pps_counter[src].append(now)
    src_pps_counter[src] = [t for t in src_pps_counter[src] if now - t <= SRC_RATE_WINDOW]

    # ---- Transport ----
    tcp = pkt.getlayer(TCP)
    udp = pkt.getlayer(UDP)

    if tcp:
        proto = "TCP"
        sport = tcp.sport
        dport = tcp.dport
    elif udp:
        proto = "UDP"
        sport = udp.sport
        dport = udp.dport
    else:
        return

    fwd_key = (src, dst, sport, dport, proto)
    rev_key = (dst, src, dport, sport, proto)

    size = len(pkt)
    now = time.time()

    # ---- EXISTING FLOW? ----
    if fwd_key in flows:
        key = fwd_key
        direction = "fwd"
    elif rev_key in flows:
        key = rev_key
        direction = "bwd"
    else:
        key = fwd_key
        flows[key] = new_flow()
        direction = "fwd"

    flow = flows[key]
    flow["last"] = now
    flow["pkt_sizes"].append(size)

    if direction == "fwd":
        flow["fwd_packets"] += 1
        flow["fwd_bytes"] += size
    else:
        flow["bwd_packets"] += 1
        flow["bwd_bytes"] += size

    # ---- Evidence PCAP ----
    if len(flow_packets[key]) < PCAP_LIMIT:
        flow_packets[key].append(pkt)

    # ---- Port scan tracking (source only) ----
    port_scan_tracker[src].append((dport, now))

    # keep only recent window
    port_scan_tracker[src] = [
        (p, t) for (p, t) in port_scan_tracker[src] if now - t <= SCAN_WINDOW
    ]



def monitor_flows():
    while True:
        try:
            time.sleep(2)
            now = time.time()
            # ---- Clean attacker profiles ----
            for ip in list(attacker_profile.keys()):
                if now - attacker_profile[ip]["last_seen"] > ATTACK_PROFILE_WINDOW:
                    attacker_profile.pop(ip, None)

            # ---- Clean port scan tracker ----
            for src in list(port_scan_tracker.keys()):
                port_scan_tracker[src] = [
                    (p, t) for (p, t) in port_scan_tracker[src]
                    if now - t <= PORT_SCAN_WINDOW
                ]

            expired = []

            for key in list(flows.keys()):
                flow = flows.get(key)
                if not flow:
                    continue

                pkt_count = flow["fwd_packets"] + flow["bwd_packets"]
                idle_time = now - flow["last"]

                # ----- only analyze when enough data OR timed out -----
                if pkt_count < MIN_PKTS_FOR_RATE and idle_time <= FLOW_TIMEOUT:
                    continue

                src_ip = key[0]
                ports = [p for (p, t) in port_scan_tracker.get(src_ip, [])]
                scan_ports = len(set(ports))

                print("[*] Flow ready for detection:", key)

                classify_flow(flow, key, scan_ports)

                # expire after classification or timeout
                expired.append(key)

            # ---- Remove expired flows & evidence ----
            for k in expired:
                flows.pop(k, None)
                flow_packets.pop(k, None)

        except Exception as e:
            print("[THREAD ERROR]", e)

# =========================
# BLOCK IP 
# =========================

def block_ip(ip):
    if ip in blocked_ips:
        print(f"[FIREWALL] Already blocked: {ip}")
        return

    try:
        if platform.system().lower() == "windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=IDS_Block_{ip}",
                "dir=in", "action=block", f"remoteip={ip}"
            ]
            subprocess.run(cmd, check=True)

        else:  # Linux / WSL
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )

        blocked_ips[ip] = time.time()
        print(f"[FIREWALL] Blocked IP: {ip}")

    except Exception as e:
        print("[FIREWALL] Block failed:", e)



def monitor_blocked_ips():
    while True:
        try:
            time.sleep(5)
            now = time.time()

            expired = []

            for ip, t in blocked_ips.items():
                if now - t >= BLOCK_DURATION:
                    unblock_ip(ip)
                    expired.append(ip)

            for ip in expired:
                blocked_ips.pop(ip, None)

        except Exception as e:
            print("[UNBLOCK THREAD ERROR]", e)


# =========================
# UNBLOCK IP 
# =========================
def unblock_ip(ip):
    try:
        if platform.system().lower() == "windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=IDS_Block_{ip}"
            ]
            subprocess.run(cmd, check=True)

        else:
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )

        print(f"[FIREWALL] Unblocked IP: {ip}")

    except Exception as e:
        print("[FIREWALL] Unblock failed:", e)

# =========================
# PCAP + LOGS
# =========================
def save_evidence(flow, key, event):
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    ts = time.strftime("%Y%m%d_%H%M%S")
    folder = os.path.join(EVIDENCE_DIR, f"{key[0]}_{ts}")
    os.makedirs(folder, exist_ok=True)

    # save pcap
    pcap_path = os.path.join(folder, "traffic.pcap")
    pkts = flow_packets.get(key, [])
    if pkts:
        wrpcap(pcap_path, pkts)

    # save json report
    report_path = os.path.join(folder, "incident.json")
    with open(report_path, "w") as f:
        json.dump(event, f, indent=2)

    print(f"[FORENSICS] Evidence saved in {folder}")

# =========================
# DYNAMIC THRESHOLD VALUES
# =========================
def dynamic_rate_threshold():
    if len(pps_history) < 30:
        return RATE_HIGH, RATE_MEDIUM

    avg = float(np.mean(pps_history))
    std = float(np.std(pps_history))

    high = max(RATE_HIGH, avg + 3 * std)
    mid = max(RATE_MEDIUM, avg + 1.5 * std)

    return high, mid


# =========================
# CAMPAIGN CHECK FUNCTION
# =========================

def check_attack_campaign(src_ip):
    now = time.time()

    # keep only recent attacks
    recent = [
        (t, a) for (t, a) in attack_history[src_ip]
        if now - t <= ATTACK_CHAIN_WINDOW
    ]

    attack_history[src_ip] = recent

    unique_attacks = set(a for _, a in recent)

    if len(unique_attacks) >= MIN_STAGES_FOR_CAMPAIGN:
        return True, list(unique_attacks)

    return False, []



# =========================
# START
# =========================

import threading
threading.Thread(target=monitor_flows, daemon=True).start()
threading.Thread(target=monitor_blocked_ips, daemon=True).start() #UNBLOCK THREAD


print("[*] Starting packet capture...")
sniff(prn=handle_packet, store=False)


