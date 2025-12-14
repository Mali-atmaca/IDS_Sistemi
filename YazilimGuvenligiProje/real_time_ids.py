# real_time_ids.py
from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import pandas as pd
import numpy as np
import joblib

WINDOW = 5

packet_times = {}
port_history = {}
last_seen = {}

# ============================
# MODEL DOSYALARI YÜKLEME
# ============================
def load_all():
    kmeans = joblib.load("kmeans_model.pkl")
    scaler = joblib.load("scaler.pkl")
    threshold = joblib.load("threshold.pkl")
    return kmeans, scaler, threshold


# ============================
# TCP FLAG ENCODE
# ============================
def flag_encode(s):
    mapping = {'F':1,'S':2,'R':4,'P':8,'A':16,'U':32,'E':64,'C':128}
    flags = 0
    if isinstance(s, str):
        for ch in s:
            if ch in mapping:
                flags |= mapping[ch]
    return flags


# ============================
# SLIDING WINDOW
# ============================
def update_window(src, ts, dport):
    if src not in packet_times:
        packet_times[src] = []
    if src not in port_history:
        port_history[src] = []

    packet_times[src].append(ts)
    port_history[src].append((ts, dport))

    cutoff = ts - WINDOW
    packet_times[src] = [t for t in packet_times[src] if t >= cutoff]
    port_history[src] = [(t,p) for (t,p) in port_history[src] if t >= cutoff]


def get_pps(src):
    if src not in packet_times:
        return 0
    return len(packet_times[src]) / WINDOW


def get_port_div(src):
    if src not in port_history:
        return 0
    return len({p for (_,p) in port_history[src]})


def get_flow_duration(src, ts):
    if src not in packet_times or len(packet_times[src]) == 0:
        return 0
    return ts - packet_times[src][0]


# ============================
# ÖZELLİK ÇIKARMA FONKSİYONU
# ============================
def extract_features(pkt):
    ts = time.time()
    if not pkt.haslayer(IP):
        return None, None, None

    src = pkt[IP].src
    dst = pkt[IP].dst

    length = len(pkt)
    protocol = 6 if pkt.haslayer(TCP) else 17 if pkt.haslayer(UDP) else 1 if pkt.haslayer(ICMP) else 0
    flags = str(pkt[TCP].flags) if pkt.haslayer(TCP) else ""

    sport = pkt.sport if hasattr(pkt, "sport") else 0
    dport = pkt.dport if hasattr(pkt, "dport") else 0

    prev_ts = last_seen.get(src, ts)
    iat = ts - prev_ts
    last_seen[src] = ts

    update_window(src, ts, dport)

    pps = get_pps(src)
    port_div = get_port_div(src)
    flow_dur = get_flow_duration(src, ts)

    features = {
        "packet_length": length,
        "protocol": protocol,
        "tcp_flags_enc": flag_encode(flags),
        "src_port": sport,
        "dst_port": dport,
        "inter_arrival_time": iat,
        "pps": pps,
        "port_diversity": port_div,
        "flow_duration": flow_dur
    }

    df = pd.DataFrame([features])
    return df, src, dst


# ============================
# SALDIRI TÜRÜ ANALİZİ
# ============================
def attack_type(pkt, df):
    pps = df["pps"].iloc[0]
    port_div = df["port_diversity"].iloc[0]

    if pkt.haslayer(ICMP) and pps > 15:
        return "ICMP Flood"

    if pkt.haslayer(TCP):
        flags = str(pkt[TCP].flags)
        if "S" in flags and pps > 20:
            return "SYN Flood"
        if port_div > 10 and pps > 5:
            return "Port Tarama"

    return None


# ============================
# ANA IDS
# ============================
def start_ids(iface=None):
    kmeans, scaler, threshold = load_all()

    print("Gerçek zamanlı IDS başlatıldı...")
    print("Eşik değeri:", threshold)

    def handle(pkt):
        df, src, dst = extract_features(pkt)
        if df is None:
            return

        scaled = scaler.transform(df)
        dist = np.min(kmeans.transform(scaled))
        anomaly = dist > threshold

        atk = attack_type(pkt, df)

        if anomaly and atk:
            print(f"[ANOMALİ + SALDIRI] {atk} | {src} -> {dst} | dist={dist:.4f}")

        elif anomaly:
            print(f"[ANOMALİ] {src} -> {dst} | dist={dist:.4f}")

        elif atk:
            print(f"[SALDIRI OLASILIGI] {atk} | {src} -> {dst}")

    sniff(prn=handle, store=False, iface=iface)
    # BELLEK TEMİZLİĞİ (EKLEME)
# ============================
def cleanup_cache():
    current_time = time.time()
    expired_ips = []
    
    # 30 saniyedir işlem görmeyen IP'leri sil
    for ip, timestamps in packet_times.items():
        if not timestamps or (current_time - timestamps[-1] > 30):
            expired_ips.append(ip)
            
    for ip in expired_ips:
        packet_times.pop(ip, None)
        port_history.pop(ip, None)
        last_seen.pop(ip, None)


if __name__ == "__main__":
    start_ids()
