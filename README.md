# Anomaly Detection System with K-Means 🛡️

Bu proje, **NSL-KDD** veri seti kullanılarak geliştirilmiş, makine öğrenmesi tabanlı bir Saldırı Tespit Sistemi (IDS) prototipidir. K-Means kümeleme algoritması kullanılarak ağ trafiğindeki anomalileri tespit eder.

## 🚀 Öne Çıkan Özellikler
* **Veri Odaklı Analiz:** `KDDTrain+` ve `KDDTest+` veri setleri üzerinde eğitim ve test süreçleri.
* **Makine Öğrenmesi:** K-Means algoritması ile trafik sınıflandırma.
* **Model Persistence:** Eğitilmiş model `anomaly_detector_kmeans_k2.pkl` olarak saklanmakta ve doğrudan yüklenebilmektedir.
* **Simülasyon:** `saldiri.py` ile tespit mekanizmasının doğrulanması.

## 🛠️ Teknik Altyapı
* **Dil:** Python
* **Algoritma:** K-Means Clustering (K=2)
* **Kütüphaneler:** Scikit-learn, Pandas, NumPy

## 📁 Dosya Yapısı ve Görevleri
| Dosya | Görev |
| :--- | :--- |
| `egitim.py` | Veri setini işleyen ve K-Means modelini eğiten betik. |
| `ids2.py` | Eğitilmiş modeli kullanarak anomali tespiti yapan ana modül. |
| `anomaly_detector_kmeans_k2.pkl` | Sistemin beyni olan, önceden eğitilmiş ML modeli. |
| `saldiri.py` | Tespit sistemini test etmek için kullanılan saldırı senaryoları. |
| `log.txt` | Sistemin çalışma sırasında ürettiği analiz kayıtları. |

## ⚙️ Hızlı Başlangıç
1. Gereksinimleri yükleyin: `pip install scikit-learn pandas`
2. Modeli eğitmek için: `python egitim.py`
3. Sistemi çalıştırmak için: `python ids2.py`

---
*Bu çalışma, yazılım güvenliği ve makine öğrenmesi prensiplerini uygulamalı olarak göstermek amacıyla hazırlanmıştır.*
