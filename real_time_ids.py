from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import pandas as pd
import numpy as np
import joblib
import sys

# ============================
# AYARLAR
# ============================
WINDOW = 2  # Saniye cinsinden zaman penceresi (KDD Count özelliği için)

# Durum takibi için global değişkenler
packet_times = {}  # IP bazlı zaman damgaları

# Model Dosyalarını Yükle
print("[*] Model dosyaları yükleniyor...")
try:
    kmeans = joblib.load("kmeans_model.pkl")
    scaler = joblib.load("scaler.pkl")
    threshold = joblib.load("threshold.pkl")
except FileNotFoundError:
    print("[HATA] Model dosyaları (.pkl) bulunamadı. Önce eğitimi çalıştırın.")
    sys.exit()

# ============================
# YARDIMCI FONKSİYONLAR
# ============================
def encode_flag_live(flags):
    """Canlı paket bayraklarını modele uygun sayıya çevirir"""
    # Sadece SYN varsa (S0 benzeri - Saldırı girişimi olabilir) -> 2
    if "S" in flags and "A" not in flags:
        return 2  
    # ACK varsa (SF benzeri - Bağlantı kurulmuş) -> 1
    if "A" in flags:
        return 1  
    return 0

def update_window(src, ts):
    """IP adresi için son WINDOW saniyedeki paketleri sayar"""
    if src not in packet_times:
        packet_times[src] = []
    
    packet_times[src].append(ts)
    # Süresi dolan eski kayıtları temizle
    packet_times[src] = [t for t in packet_times[src] if t >= ts - WINDOW]

def get_pps(src):
    """Saniyedeki paket sayısını (veya penceredeki) döndürür"""
    return len(packet_times.get(src, []))

# ============================
# ÖZELLİK ÇIKARMA (FEATURE EXTRACTION)
# ============================
def extract_features(pkt):
    ts = time.time()
    
    # Sadece IP paketlerini işle
    if not pkt.haslayer(IP):
        return None, None

    src = pkt[IP].src
    update_window(src, ts) # Zaman penceresini güncelle

    # 1. Protocol (TCP=6, UDP=17, ICMP=1)
    if pkt.haslayer(TCP):
        protocol = 6
        flags_str = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        protocol = 17
        flags_str = "" # UDP'de bayrak yoktur
    elif pkt.haslayer(ICMP):
        protocol = 1
        flags_str = ""
    else:
        protocol = 0
        flags_str = ""

    # Modelin beklediği özellik sözlüğü
    features = {
        "duration": 0,                   # Canlı pakette süre ölçmek zordur, 0 kabul ediyoruz
        "protocol": protocol,
        "flag_enc": encode_flag_live(flags_str),
        "src_bytes": len(pkt),           # Paket boyutu
        "dst_bytes": 0,                  # Tek yönlü dinlemede gelen yanıtı bilemeyiz
        "count": get_pps(src),           # Son 2 saniyedeki paket sayısı
        "srv_count": 1,                  # Basitleştirme
        "serror_rate": 1 if "S" in flags_str and "A" not in flags_str else 0, # SYN hatası oranı
        "diff_srv_rate": 0
    }

    # DataFrame oluştururken SÜTUN SIRASINI modelle aynı yapıyoruz
    columns_order = [
        "duration", "protocol", "flag_enc", "src_bytes", "dst_bytes", 
        "count", "srv_count", "serror_rate", "diff_srv_rate"
    ]
    
    return pd.DataFrame([features], columns=columns_order), src

# ============================
# SALDIRI TİPİ TANIMLAMA
# ============================
def detect_attack_type(pkt, count):
    """Anomali tespit edildiyse türünü tahmin etmeye çalışır"""
    
    # 1. ICMP Flood: ICMP paketi ve yüksek sayı
    if pkt.haslayer(ICMP) and count > 10:
        return "ICMP Flood (Ping Saldırısı)"

    # 2. SYN Flood: TCP SYN bayrağı var ve yüksek sayı
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if "S" in flags and "A" not in flags and count > 10:
            return "SYN Flood (DoS Saldırısı)"
        
        # 3. Port Tarama: Çok hızlı paket gönderimi (Kısa sürede çok bağlantı)
        if count > 5:
            return "Port Tarama (Şüpheli Hız)"

    return "Bilinmeyen Anomali"

# ============================
# ANA DÖNGÜ
# ============================
def start_ids():
    print(f"[*] IDS Başlatıldı. Eşik Değer: {threshold:.4f}")
    print("[*] Ağ trafiği dinleniyor... (Durdurmak için CTRL+C)")

    def packet_callback(pkt):
        try:
            df_features, src_ip = extract_features(pkt)
            
            if df_features is None:
                return

            # Normalizasyon
            scaled_features = scaler.transform(df_features)
            
            # K-Means Uzaklık Hesabı
            dist = np.min(kmeans.transform(scaled_features))
            
            # Karar Aşaması
            is_anomaly = dist > threshold

            if is_anomaly:
                # Özellikteki 'count' değerini al
                current_count = df_features["count"].iloc[0]
                attack_name = detect_attack_type(pkt, current_count)
                
                print(f"[ALARM] {attack_name} | Kaynak: {src_ip} | Uzaklık: {dist:.2f}")
            else:
                # Normal paketleri ekrana basmıyoruz (terminal kirlenmesin diye)
                # İstersen burayı açabilirsin:
                # print(f"[NORMAL] {src_ip} | Uzaklık: {dist:.2f}")
                pass

        except Exception as e:
            # Hata olursa program çökmesin, hatayı yazsın
            print(f"[HATA] {e}")

    # Sniffing (Dinleme) Başlat
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    start_ids()