import sys
from scapy.all import Ether, ARP, sendp

def test_arp_spoof_detection():
    LOCAL_GATEAWAY_ROUTER_IP = "192.168.0.1"
    MY_NETWORK_ADAPTER_NAME = "Realtek PCIe GbE Family Controller"
    
    fake_mac = "FF:FF:FF:FF:FF:FF"

    print(f"Send ARP Packet: {LOCAL_GATEAWAY_ROUTER_IP} -> {fake_mac}")

    ether_layer = Ether(dst="FF:FF:FF:FF:FF:FF")

    arp_layer = ARP(
        op=2,
        psrc=LOCAL_GATEAWAY_ROUTER_IP,
        hwsrc=fake_mac,
        hwdst="FF:FF:FF:FF:FF:FF"
    )

    packet = ether_layer / arp_layer

    for _ in range(1):
        sendp(packet, iface=MY_NETWORK_ADAPTER_NAME, verbose=True)

if __name__ == "__main__":
    try:
        test_arp_spoof_detection()
    except PermissionError:
        print("[ERROR] Запусти скрипт с правами суперпользователя (через sudo)!", file=sys.stderr)