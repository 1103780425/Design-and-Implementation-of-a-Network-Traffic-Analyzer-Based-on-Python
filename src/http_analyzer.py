from scapy.all import sniff, TCP, IP
import re

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].dport == 80 or packet[TCP].dport == 443:
            payload = str(packet[TCP].payload)
            if "HTTP" in payload:
                print("HTTP Request Detected:")
                parse_http_request(payload)

def parse_http_request(http_payload):
    try:
        headers_raw = http_payload.split(r"\r\n\r\n")[0]
        headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers_raw))
        print("Request Path:", headers.get("Path"))
        print("Host:", headers.get("Host"))
        print("User-Agent:", headers.get("User-Agent"))
    except Exception as e:
        print(f"Failed to parse HTTP headers: {str(e)}")

def start_sniffing(timeout=60):
    print("Starting HTTP sniffer...")
    sniff(filter="tcp", prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()
