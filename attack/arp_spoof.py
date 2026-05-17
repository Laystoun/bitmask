import sys
from scapy.all import Ether, ARP, sendp

def test_arp_spoof_detection():
    target_ip = "192.168.0.1" 
    
    fake_mac = "FF:FF:FF:FF:FF:FF"

    print(f"Send ARP Packet: {target_ip} -> {fake_mac}")

    ether_layer = Ether(dst="FF:FF:FF:FF:FF:FF")

    arp_layer = ARP(
        op=2,
        psrc=target_ip,
        hwsrc=fake_mac,
        hwdst="FF:FF:FF:FF:FF:FF"
    )

    packet = ether_layer / arp_layer

    for _ in range(1):
        sendp(packet, iface='Realtek PCIe GbE Family Controller', verbose=True)

if __name__ == "__main__":
    try:
        test_arp_spoof_detection()
    except PermissionError:
        print("[ERROR] Запусти скрипт с правами суперпользователя (через sudo)!", file=sys.stderr)