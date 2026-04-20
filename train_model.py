# train_model.py
import os
os.environ["OMP_NUM_THREADS"] = "1"
import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.cluster import KMeans
import joblib

# ============================
# TCP FLAG ENCODE (class yok)
# ============================
def encode_tcp_flags(s):
    if not isinstance(s, str):
        return 0
    mapping = {'F':1, 'S':2, 'R':4, 'P':8, 'A':16, 'U':32, 'E':64, 'C':128}
    flags = 0
    for ch in s:
        if ch in mapping:
            flags |= mapping[ch]
    return flags


# ============================
# ÖZELLİK SEÇİMİ (class yok)
# ============================
def prepare_dataset(df):
    df = df.copy()

    df["tcp_flags_enc"] = df["tcp_flags"].apply(encode_tcp_flags)

    df["protocol"] = pd.to_numeric(df["protocol"], errors="coerce").fillna(0)
    df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce").fillna(0)
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)

    features = [
        "packet_length",
        "protocol",
        "tcp_flags_enc",
        "src_port",
        "dst_port",
        "inter_arrival_time",
        "pps",
        "port_diversity",
        "flow_duration"
    ]

    X = df[features].apply(pd.to_numeric, errors="coerce").fillna(0)
    return X


# ============================
# MODEL EĞİTİMİ (class yok)
# ============================
def train_model(csv_file="traffic.csv"):
    print("Veri yükleniyor:", csv_file)
    df = pd.read_csv(csv_file)

    X = prepare_dataset(df)

    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
    kmeans.fit(X_scaled)

    distances = kmeans.transform(X_scaled).min(axis=1)

    threshold = np.quantile(distances, 0.995)

    joblib.dump(kmeans, "kmeans_model.pkl")
    joblib.dump(scaler, "scaler.pkl")
    joblib.dump(threshold, "threshold.pkl")

    print("Model kaydedildi.")
    print("Eşik Değeri:", threshold)


# ============================
# ANA ÇALIŞTIRMA
# ============================
if __name__ == "__main__":
    train_model("traffic.csv")
