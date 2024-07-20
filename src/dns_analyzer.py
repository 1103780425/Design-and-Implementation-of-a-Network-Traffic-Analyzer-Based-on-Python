# dns_analyzer
from scapy.all import sniff, DNS, DNSQR, IP

def dns_callback(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query_layer = packet[DNSQR]
        print(f"DNS Query: {query_layer.qname.decode('utf-8')} for type {query_layer.qtype}")

def start_sniffing(timeout=60):
    print("Starting DNS traffic sniffing...")
    sniff(filter="udp port 53", prn=dns_callback, store=0)

if __name__ == "__main__":
    start_sniffing()
