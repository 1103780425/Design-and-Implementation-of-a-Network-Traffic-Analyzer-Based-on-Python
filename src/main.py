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

    monitor = TrafficMonitor(window_size=10, threshold=100)  # Customize as needed

    def handle_packet(packet):
        monitor.process_packet(packet)

    sniff(prn=handle_packet)  # Use Scapy to capture and process packets

if __name__ == "__main__":
    main()
