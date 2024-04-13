# capture.py
import scapy.all as scapy

def capture_packets(interface='eth0', count=10):
    """
    Capture packets from the network.
    :param interface: Network interface to capture from.
    :param count: Number of packets to capture.
    :return: a list of captured packets.
    """
    packets = scapy.sniff(iface=interface, count=count)
    return packets
