import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import joblib  # Modeli ve scaler'ı kaydetmek için
import os

# =============================================================================
# AYARLAR VE SABİTLER
# =============================================================================
DOSYA_YOLU = 'KDDTrain+.txt'  # Veri setinin yolu
MODEL_DOSYASI = 'kmeans_model.pkl'
SCALER_DOSYASI = 'scaler.pkl'
THRESHOLD_DOSYASI = 'threshold.txt'

# NSL-KDD Veri Seti Sütun İsimleri (Veri setinde başlık olmadığı için biz ekliyoruz)
# Kaynak: NSL-KDD dökümantasyonu
SUTUNLAR = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", 
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", 
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", 
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", 
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", 
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", 
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", 
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", 
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

def veri_yukle_ve_hazirla(dosya_yolu):
    """
    Veri setini yükler, gerekli sütunları seçer ve temizler.
    """
    print(f"[BİLGİ] Veri seti yükleniyor: {dosya_yolu}...")
    try:
        df = pd.read_csv(dosya_yolu, names=SUTUNLAR, index_col=False)
    except FileNotFoundError:
        print("[HATA] Veri seti dosyası bulunamadı! Lütfen dosya yolunu kontrol edin.")
        return None

    print(f"[BİLGİ] Veri seti boyutu: {df.shape}")

    # --- ÖNEMLİ ADIM: ÖZELLİK SEÇİMİ ---
    # Canlı trafikte (Scapy ile) kolayca yakalayabileceğimiz ve sayısal olan sütunları seçiyoruz.
    # IP ve Port bilgisi 'model eğitimi' için kullanılmaz, 'raporlama' için kullanılır.
    # Model sadece paketin fiziksel özelliklerine (boyut, süre) odaklanmalı.
    
    secilen_ozellikler = ['duration', 'src_bytes', 'dst_bytes']
    
    # Yeni bir DataFrame oluşturuyoruz
    X = df[secilen_ozellikler].copy()
    
    print(f"[BİLGİ] Seçilen özellikler: {secilen_ozellikler}")
    return X

def modeli_egit_ve_kaydet(X):
    """
    Veriyi normalize eder, K-Means modelini eğitir ve eşik değerini hesaplar.
    """
    
    # 1. NORMALİZASYON (Standardizasyon)
    # K-Means uzaklık temelli olduğu için verilerin aynı ölçekte olması şarttır.
    # Örneğin: 'duration' 0-5 arası iken 'src_bytes' 0-10000 arası olabilir. Bunu dengeliyoruz.
    print("[BİLGİ] Veri normalize ediliyor (StandardScaler)...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 2. K-MEANS MODEL EĞİTİMİ
    # K=2 seçiyoruz: Biri genel 'Normal' trafik, diğeri 'Diğer/Anormal' eğilimli kümeler olabilir.
    # Veya veriyi 2 ana öbekte toplamak için.
    k_sayisi = 2
    print(f"[BİLGİ] K-Means modeli eğitiliyor (Küme Sayısı: {k_sayisi})...")
    kmeans = KMeans(n_clusters=k_sayisi, random_state=42, n_init=10)
    kmeans.fit(X_scaled)

    # 3. EŞİK DEĞER (THRESHOLD) HESAPLAMA
    # Her noktanın kendi küme merkezine olan uzaklığını hesaplıyoruz.
    # Ödev metninde: "En uzak %5'lik veri anomali olarak kabul edilerek eşik değer ayarlanabilir" deniyor.
    
    # Tüm verilerin merkezlere uzaklığını al (transform fonksiyonu uzaklık matrisi döndürür)
    uzakliklar_matrisi = kmeans.transform(X_scaled)
    
    # Her veri noktası için en yakın merkeze olan uzaklığı bul (min uzaklık)
    en_yakin_uzakliklar = np.min(uzakliklar_matrisi, axis=1)
    
    # %95'lik dilimi (percentile) eşik değer olarak belirle
    esik_deger = np.percentile(en_yakin_uzakliklar, 95)
    
    print(f"[SONUÇ] Hesaplanan Anomali Eşik Değeri (Threshold): {esik_deger:.4f}")
    print("[BİLGİ] Bu değerin üzerindeki uzaklığa sahip paketler 'ANOMALİ' sayılacak.")

    # 4. KAYDETME İŞLEMİ (Canlı Dinleme için Şart)
    print("[BİLGİ] Model ve parametreler kaydediliyor...")
    joblib.dump(kmeans, MODEL_DOSYASI)
    joblib.dump(scaler, SCALER_DOSYASI)
    
    with open(THRESHOLD_DOSYASI, "w") as f:
        f.write(str(esik_deger))
        
    print(f"[BAŞARILI] Dosyalar oluşturuldu:\n- {MODEL_DOSYASI}\n- {SCALER_DOSYASI}\n- {THRESHOLD_DOSYASI}")

if __name__ == "__main__":
    # Ana akış
    veriler = veri_yukle_ve_hazirla(DOSYA_YOLU)
    
    if veriler is not None:
        modeli_egit_ve_kaydet(veriler)