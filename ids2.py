# -*- coding: utf-8 -*-
"""
REAL-TIME IDS (K=2 UYUMLU)
✔ SPYDER + TERMINAL RENK DESTEKLİ
✔ SALDIRI ÇIKTISI GELİŞTİRİLMİŞ
✔ LOG KAYDI VAR
"""
import pickle
import numpy as np
import pandas as pd
import os
import time
from collections import deque
from datetime import datetime

# ---- Renk Desteği ----
from colorama import init, Fore, Style
init(autoreset=True)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    print("❌ Scapy bulunamadı. pip install scapy yaz")
    SCAPY_AVAILABLE = False


# ===============================
# MODEL YÜKLE
# ===============================
MODEL_PATH = "anomaly_detector_kmeans_k2.pkl"
if not os.path.exists(MODEL_PATH):
    print(f"❌ {MODEL_PATH} bulunamadı!")
    exit()

with open(MODEL_PATH, "rb") as f:
    model_data = pickle.load(f)

kmeans = model_data["kmeans"]
scaler = model_data["scaler"]
pca = model_data["pca"]
label_encoders = model_data["label_encoders"]
thresholds = model_data["thresholds_per_cluster"]
centers = model_data["cluster_centers"]
FEATURES = model_data["minimal_features"]

traffic_window = deque()
WINDOW_SEC = 2.0


# ===============================
# YARDIMCI FONKSİYONLAR
# ===============================
def map_service(port):
    mapping = {80:"http", 443:"http", 21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"domain"}
    return mapping.get(int(port), "other")

def safe_encode(col, val):
    le = label_encoders[col]
    return le.transform([val])[0] if val in le.classes_ else le.transform([le.classes_[0]])[0]


# ===============================
# FEATURE ÇIKAR
# ===============================
def extract_features(pkt):
    if not IP in pkt:
        return None
    
    src, dst = pkt[IP].src, pkt[IP].dst
    byte_len = len(pkt[IP])
    is_https = False
    
    if pkt.haslayer(TCP):
        proto, sport, dport = "tcp", pkt[TCP].sport, pkt[TCP].dport
        srv = map_service(dport)

        if dport == 443 or sport == 443:
            is_https = True
        
        f = pkt[TCP].flags
        flag = "S0" if (f & 0x02) and not (f & 0x10) else "SF"
        serror = 1 if flag == "S0" else 0
        logged_in = 1 if (f & 0x08) else 0

    elif pkt.haslayer(UDP):
        proto, sport, dport = "udp", pkt[UDP].sport, pkt[UDP].dport
        srv = map_service(dport)
        flag = "SF"
        serror = 0
        logged_in = 0

    elif pkt.haslayer(ICMP):
        proto, sport, dport = "icmp", 0, 0
        srv = "eco_i"
        flag = "SF"
        serror = 0
        logged_in = 0
    else:
        return None


    now = time.time()
    traffic_window.append({'time': now, 'src': src, 'dst': dst, 'srv': srv, 'sport': sport, 'serror': serror})
    
    while traffic_window and (now - traffic_window[0]['time'] > WINDOW_SEC):
        traffic_window.popleft()
        
    count = srv_count = serror_sum = 0
    src_ports = set()
    diff_srv_set = set()
    
    for p in traffic_window:
        if p['dst'] == dst:
            count += 1
            if p['srv'] == srv:
                srv_count += 1
            if p['serror']:
                serror_sum += 1
            if p['src'] == src:
                diff_srv_set.add(p['srv'])
                src_ports.add(p['sport'])

    serror_rate = serror_sum / count if count > 0 else 0
    same_srv_rate = srv_count / count if count > 0 else 0
    diff_srv_rate = len(diff_srv_set) / count if count > 0 else 0
    src_port_rate = len(src_ports) / count if count > 0 else 0


    data = {
        'protocol_type': proto, 'service': srv, 'flag': flag,
        'src_bytes': byte_len, 'dst_bytes': 0, 'duration': 0, 'logged_in': logged_in,
        'count': count, 'srv_count': srv_count,
        'serror_rate': serror_rate, 'same_srv_rate': same_srv_rate, 'diff_srv_rate': diff_srv_rate,
        'dst_host_count': count, 'dst_host_srv_count': srv_count,
        'dst_host_same_srv_rate': same_srv_rate, 
        'dst_host_diff_srv_rate': diff_srv_rate,
        'dst_host_same_src_port_rate': src_port_rate,
        'dst_host_serror_rate': serror_rate
    }
    
    df = pd.DataFrame([data])[FEATURES]

    for c in ['src_bytes','dst_bytes','duration','count','srv_count','dst_host_count','dst_host_srv_count']:
        df[c] = np.log1p(df[c])
    
    for c in ['protocol_type','service','flag']:
        df[c] = df[c].apply(lambda x: safe_encode(c, x))
        
    return df, (src, dst, proto, srv, is_https)


# ===============================
# IDS CORE
# ===============================
def ids_process(pkt):
    try:
        res = extract_features(pkt)
        if res is None:
            return
        
        df, info = res
        src, dst, proto, srv, is_https = info

        scaled = scaler.transform(df.values)
        pca_out = pca.transform(scaled)
        
        dists = np.linalg.norm(centers - pca_out[0], axis=1)
        nearest = np.argmin(dists)
        dist = dists[nearest]
        
        current_threshold = thresholds[nearest]
        if is_https:
            current_threshold *= 1.2


        # =========================
        # SALDIRI FORMATLI ÇIKTI
        # =========================
        if dist > current_threshold:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            print(Fore.LIGHTRED_EX + "\n" + "="*70)
            print("🔴  ANOMALİ / SALDIRI ALGILANDI")
            print("="*70)
            print(f"🕒 Zaman        : {now}")
            print(f"📌 Kaynak IP    : {src}")
            print(f"🎯 Hedef IP     : {dst}")
            print(f"🚦 Protokol     : {proto}")
            print(f"🛠 Servis       : {srv}")
            print(f"📏 Mesafe       : {dist:.2f}")
            print(f"🎯 Eşik Değeri  : {current_threshold:.2f}")
            print("="*70 + Style.RESET_ALL)

            with open("log.txt","a",encoding="utf-8") as log:
                log.write(f"[{now}] ATTACK SRC:{src} DST:{dst} PROTO:{proto} "
                          f"SRV:{srv} DIST:{dist:.2f}/{current_threshold:.2f}\n")

        else:
            print(Fore.LIGHTGREEN_EX +
                  f"✔ NORMAL [{src} -> {dst}] "
                  f"Proto:{proto} Srv:{srv} "
                  f"Dist:{dist:.2f}/{current_threshold:.2f}" +
                  Style.RESET_ALL)

    except Exception:
        pass


# ===============================
# START
# ===============================
if __name__ == "__main__":
    if SCAPY_AVAILABLE:
        print("📡 IDS Aktif - HTTPS için 1.2x tolerans uygulanıyor...")
        sniff(prn=ids_process, store=False, filter="ip")
