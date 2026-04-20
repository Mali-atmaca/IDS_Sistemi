# -*- coding: utf-8 -*-

import os
import numpy as np
import pandas as pd
import pickle

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans

os.environ["LOKY_MAX_CPU_COUNT"] = "8"

# =========================
# AYARLAR
# =========================
K_CLUSTERS = 2             # İsteğin üzerine k=2
THRESHOLD_PERCENTILE = 95  # %98'den %93'e çektik (Saldırıları yakalamak için sıkılaştırma)
PCA_VARIANCE = 0.99        # Veri kaybını en aza indirmek için artırdık

# =========================
# GÜÇLÜ FEATURE SET (Saldırı İmbaları)
# =========================
MINIMAL_FEATURES = [
    'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'duration', 'logged_in',
    'count', 'srv_count', 'serror_rate', 'same_srv_rate', 'diff_srv_rate',
    'dst_host_count', 'dst_host_srv_count', 
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_serror_rate'
]

print("=" * 70)
print(f"🎯 KMEANS k={K_CLUSTERS} | Threshold=%{THRESHOLD_PERCENTILE} | OPTİMİZE MODEL")
print("=" * 70)

# =========================
# 1. VERİ YÜKLEME
# =========================
cols = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'class','difficulty_level'
]

if not os.path.exists("KDDTrain+.txt"):
    print("❌ HATA: KDDTrain+.txt dosyası yok!")
    exit()

df = pd.read_csv("KDDTrain+.txt", header=None)
df.columns = cols

if os.path.exists("KDDTest+.txt"):
    df_test = pd.read_csv("KDDTest+.txt", header=None)
    df_test.columns = cols
else:
    df_test = pd.DataFrame(columns=cols)

print(f"✅ Veri Yüklendi -> Train: {len(df):,}, Test: {len(df_test):,}")

# =========================
# 2. ÖN İŞLEME (LOG + ENCODING)
# =========================
df_normal = df[df['class'] == 'normal'].copy()

X_normal = df_normal[MINIMAL_FEATURES].copy()
X_all = df[MINIMAL_FEATURES].copy()
X_test = df_test[MINIMAL_FEATURES].copy() if len(df_test) > 0 else None

# Label Encoding
CAT_FEATURES = ['protocol_type', 'service', 'flag']
label_encoders = {}

for col in CAT_FEATURES:
    le = LabelEncoder()
    all_vals = pd.concat([df[col], df_test[col]], axis=0).astype(str).unique()
    le.fit(all_vals)
    
    X_normal[col] = le.transform(X_normal[col].astype(str))
    X_all[col] = le.transform(X_all[col].astype(str))
    if X_test is not None:
        X_test[col] = le.transform(X_test[col].astype(str))
    label_encoders[col] = le

# Log Transform
def apply_log(df_in):
    temp = df_in.copy()
    log_cols = ['src_bytes', 'dst_bytes', 'duration', 'count', 'srv_count', 'dst_host_count', 'dst_host_srv_count']
    for c in log_cols:
        if c in temp.columns:
            temp[c] = np.log1p(temp[c])
    return temp

X_normal = apply_log(X_normal)
X_all = apply_log(X_all)
if X_test is not None:
    X_test = apply_log(X_test)

# Scaling
scaler = StandardScaler()
X_normal_scaled = scaler.fit_transform(X_normal.values)
X_all_scaled = scaler.transform(X_all.values)
if X_test is not None:
    X_test_scaled = scaler.transform(X_test.values)

# PCA
pca = PCA(n_components=PCA_VARIANCE, random_state=42)
X_normal_pca = pca.fit_transform(X_normal_scaled)
X_all_pca = pca.transform(X_all_scaled)
if X_test is not None:
    X_test_pca = pca.transform(X_test_scaled)

print(f"✔ PCA Bileşen Sayısı: {X_normal_pca.shape[1]}")

# =========================
# 3. MODEL EĞİTİMİ (k=2)
# =========================
kmeans = KMeans(n_clusters=K_CLUSTERS, random_state=42, n_init=10)
labels_normal = kmeans.fit_predict(X_normal_pca)
cluster_centers = kmeans.cluster_centers_

# Threshold Hesaplama
thresholds_per_cluster = {}
for c in range(K_CLUSTERS):
    mask = labels_normal == c
    if np.sum(mask) > 0:
        dists = np.linalg.norm(X_normal_pca[mask] - cluster_centers[c], axis=1)
        thresholds_per_cluster[c] = np.percentile(dists, THRESHOLD_PERCENTILE)
    else:
        thresholds_per_cluster[c] = 0

print(f"✔ Thresholdlar: {thresholds_per_cluster}")

# =========================
# 4. TESPİT VE PERFORMANS
# =========================
def predict_anomaly(X_pca):
    dists = np.linalg.norm(X_pca[:, np.newaxis] - cluster_centers, axis=2)
    nearest = np.argmin(dists, axis=1)
    min_dists = dists[np.arange(len(dists)), nearest]
    thrs = np.array([thresholds_per_cluster[c] for c in nearest])
    return min_dists > thrs

def print_scores(name, y_true, y_pred):
    tp = np.sum(y_pred & y_true)
    fp = np.sum(y_pred & ~y_true)
    tn = np.sum(~y_pred & ~y_true)
    fn = np.sum(~y_pred & y_true)
    
    acc = (tp + tn) / len(y_true)
    prec = tp/(tp+fp) if (tp+fp)>0 else 0
    rec = tp/(tp+fn) if (tp+fn)>0 else 0
    f1 = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0
    
    print(f"\n📊 {name} SONUÇLARI")
    print("-" * 30)
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1 Score : {f1:.4f}")
    print(f"Detay    : TP={tp}, FP={fp}, TN={tn}, FN={fn}")

# Train Performansı
y_train_true = (df['class'] != 'normal').values
pred_train = predict_anomaly(X_all_pca)
print_scores("TRAIN", y_train_true, pred_train)

# Test Performansı
if X_test is not None:
    y_test_true = (df_test['class'] != 'normal').values
    pred_test = predict_anomaly(X_test_pca)
    print_scores("TEST", y_test_true, pred_test)

# =========================
# KAYDET
# =========================
model_data = {
    "kmeans": kmeans,
    "scaler": scaler,
    "pca": pca,
    "label_encoders": label_encoders,
    "thresholds_per_cluster": thresholds_per_cluster,
    "cluster_centers": cluster_centers,
    "minimal_features": MINIMAL_FEATURES
}

with open("anomaly_detector_kmeans_k2.pkl", "wb") as f:
    pickle.dump(model_data, f)
print("\n💾 Model Kaydedildi: anomaly_detector_kmeans_k2.pkl")

# =====================================================================
# 5. GRAFİK OLUŞTURMA ve PNG KAYDETME
# =====================================================================
import matplotlib.pyplot as plt

def calculate_metrics(y_true, y_pred):
    tp = int(np.sum(y_pred & y_true))
    fp = int(np.sum(y_pred & ~y_true))
    tn = int(np.sum(~y_pred & ~y_true))
    fn = int(np.sum(~y_pred & y_true))

    acc = (tp + tn) / len(y_true)
    prec = tp/(tp+fp) if (tp+fp)>0 else 0
    rec = tp/(tp+fn) if (tp+fn)>0 else 0
    f1 = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0

    return acc, prec, rec, f1, tp, fp, tn, fn


# Train metrikleri
train_acc, train_prec, train_rec, train_f1, tp, fp, tn, fn = calculate_metrics(y_train_true, pred_train)

# Test metrikleri
if X_test is not None:
    test_acc, test_prec, test_rec, test_f1, tp_t, fp_t, tn_t, fn_t = calculate_metrics(y_test_true, pred_test)

# --- TRAIN METRICS ---
plt.figure(figsize=(8,6))
labels = ["Accuracy", "Precision", "Recall", "F1"]
train_values = [train_acc, train_prec, train_rec, train_f1]
plt.bar(labels, train_values, color="green")
plt.ylim(0,1)
plt.title("TRAIN Performans Metrikleri")
plt.ylabel("Skor")
plt.savefig("train_metrics.png", dpi=300)
plt.close()
print("📌 train_metrics.png kaydedildi")

# --- TEST METRICS ---
if X_test is not None:
    plt.figure(figsize=(8,6))
    test_values = [test_acc, test_prec, test_rec, test_f1]
    plt.bar(labels, test_values, color="blue")
    plt.ylim(0,1)
    plt.title("TEST Performans Metrikleri")
    plt.ylabel("Skor")
    plt.savefig("test_metrics.png", dpi=300)
    plt.close()
    print("📌 test_metrics.png kaydedildi")

# --- TRAIN CONFUSION ---
plt.figure(figsize=(7,5))
plt.bar(["TP","FP","TN","FN"], [tp, fp, tn, fn], color=["green","red","green","red"])
plt.title("TRAIN Doğru / Yanlış Tespit Dağılımı")
plt.savefig("train_confusion.png", dpi=300)
plt.close()
print("📌 train_confusion.png kaydedildi")

# --- TEST CONFUSION ---
if X_test is not None:
    plt.figure(figsize=(7,5))
    plt.bar(["TP","FP","TN","FN"], [tp_t, fp_t, tn_t, fn_t], color=["green","red","green","red"])
    plt.title("TEST Doğru / Yanlış Tespit Dağılımı")
    plt.savefig("test_confusion.png", dpi=300)
    plt.close()
    print("📌 test_confusion.png kaydedildi")

print("🎯 Grafik üretimi tamamlandı. PNG dosyaları oluşturuldu.")

# =====================================================================
# 6. KÜME MERKEZLERİNE UZAKLIK GRAFİĞİ
# =====================================================================

# Eğitimde kullanılan NORMAL veriler için her küme özelinde
# merkeze uzaklık dağılımı histogramı + threshold çizgisi
for c in range(K_CLUSTERS):
    mask = labels_normal == c
    if np.sum(mask) == 0:
        continue

    dists_c = np.linalg.norm(X_normal_pca[mask] - cluster_centers[c], axis=1)
    
    plt.figure(figsize=(8,6))
    plt.hist(dists_c, bins=50, alpha=0.7)
    thr = thresholds_per_cluster.get(c, None)
    if thr is not None:
        plt.axvline(thr, linestyle="--", linewidth=2)
    
    plt.title(f"Küme {c} - Merkeze Uzaklık Dağılımı")
    plt.xlabel("Uzaklık")
    plt.ylabel("Frekans")
    
    fname = f"cluster_{c}_distance_hist.png"
    plt.savefig(fname, dpi=300)
    plt.close()
    print(f"📌 {fname} kaydedildi")

print("📊 Küme merkezlerine uzaklık grafikleri de üretildi.")


# =====================================================================
# 7. İKİ KÜME MERKEZİNİN BİRLİKTE GÖRÜLDÜĞÜ GRAFİK
# =====================================================================
import matplotlib.pyplot as plt

if X_normal_pca.shape[1] >= 2:

    plt.figure(figsize=(8,6))

    # Normal verilerin PCA dağılımı
    plt.scatter(
        X_normal_pca[:,0],
        X_normal_pca[:,1],
        s=10,
        alpha=0.4,
        label="Normal Veri"
    )

    # Küme merkezleri
    plt.scatter(
        cluster_centers[:,0],
        cluster_centers[:,1],
        s=250,
        c=["red","blue"],
        marker="X",
        edgecolors="black",
        linewidths=2,
        label="Küme Merkezleri"
    )

    for idx, center in enumerate(cluster_centers):
        plt.text(center[0]+0.02, center[1]+0.02, f"Cluster {idx}", fontsize=12)

    plt.title("PCA Uzayında İki Küme Merkezi ve Veri Dağılımı")
    plt.xlabel("PCA 1")
    plt.ylabel("PCA 2")
    plt.legend()
    plt.grid()

    plt.savefig("cluster_centers_visual.png", dpi=300)
    plt.close()

    print("📌 cluster_centers_visual.png kaydedildi")
else:
    print("⚠️ PCA bileşeni 2'den küçük olduğu için küme merkezleri grafiği çizilemedi.")
