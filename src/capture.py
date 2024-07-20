import scapy.all as scapy
import argparse
import sys

def capture_packets(interface='eth0', count=10, filter=None):
    """
    Capture packets from the network.
    :param interface: Network interface to capture from.
    :param count: Number of packets to capture.
    :param filter: BPF (Berkeley Packet Filter) string to filter captured packets.
    :return: a list of captured packets.
    """
    # try:
    #     packets = scapy.sniff(iface=interface, count=count, filter=filter, store=True)
    #     return packets
    # except Exception as e:
    #     sys.stderr.write(f"Error: {str(e)}\n")
    #     return None
    try:
        packets = scapy.sniff(iface=interface, count=count, filter=filter, store=True)
        print("Captured packets:")
        for packet in packets:
            if scapy.IP in packet:  # Check if the packet contains an IP layer
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                print(f"Packet: {src_ip} -> {dst_ip}")  # Print source and destination IP addresses
        return packets
    except Exception as e:
        print(f"Error capturing packets: {e}", file=sys.stderr)
        return None

def main():
    # parser = argparse.ArgumentParser(description='Capture network packets.')
    # parser.add_argument('--interface', type=str, default='eth0', help='Network interface to capture from')
    # parser.add_argument('--count', type=int, default=10, help='Number of packets to capture')
    # parser.add_argument('--filter', type=str, help='BPF filter for capturing packets')
    # args = parser.parse_args()

    # packets = capture_packets(interface=args.interface, count=args.count, filter=args.filter)
    # if packets:
    #     for packet in packets:
    #         print(packet.summary())
    parser = argparse.ArgumentParser(description='Capture network packets.')
    parser.add_argument('--interface', type=str, default='Intel(R) Ethernet Connection (12) I219-V', help='Network interface to capture from')
    parser.add_argument('--count', type=int, default=10, help='Number of packets to capture')
    parser.add_argument('--filter', type=str, default='ip', help='BPF filter for capturing packets')
    args = parser.parse_args()

    packets = capture_packets(interface=args.interface, count=args.count, filter=args.filter)
    if not packets:
        print("No packets captured.", file=sys.stderr)

if __name__ == '__main__':
    main()
