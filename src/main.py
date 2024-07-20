# main.py
from capture import capture_packets
from analyze import analyze_packets
from scapy.all import sniff
from traffic_monitor import TrafficMonitor

def main():
    print("Starting packet capture...")
    packets = capture_packets(interface='Intel(R) Ethernet Connection (12) I219-V', count=10)
    print("Analyzing packets...")
    analyze_packets(packets)

    monitor = TrafficMonitor(window_size=10, threshold=100)  # 根据需要定制 Customize as needed

    def handle_packet(packet):
        monitor.process_packet(packet)

    print("Starting real-time packet monitoring...")
    sniff(prn=handle_packet, timeout=100)  # 使用 Scapy 捕捉和处理数据包 Use Scapy to capture and process packets

if __name__ == "__main__":
    main()
