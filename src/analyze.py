# # analyze.py

# def analyze_packets(packets):
#     """
#     Analyze captured packets.
#     :param packets: a list of packets to analyze.
#     :return: Analysis results.
#     """
#     for packet in packets:
#         # 这里可以添加更多的分析逻辑
#         print(packet.summary())

from collections import Counter
from scapy.all import TCP

def analyze_packets(packets):
    """
    Analyze captured packets.
    :param packets: a list of packets to analyze.
    :return: Analysis results.
    """
    protocols = Counter()  # 统计各种协议的使用
    tcp_flags = Counter()  # 统计TCP标志位的使用

    for packet in packets:
        layer = packet
        while layer:
            layer_name = layer.name
            protocols[layer_name] += 1
            layer = layer.payload

        # 对TCP标志位进行统计
        if TCP in packet:
            flag = packet[TCP].flags
            tcp_flags[flag] += 1

    print("\nProtocol Usage Summary:")
    for protocol, count in protocols.items():
        print(f"{protocol}: {count}")

    print("\nTCP Flags Usage Summary:")
    for flag, count in tcp_flags.items():
        # 使用 sprint 方法来格式化标志位
        flags_description = TCP(flags=flag).sprintf("%TCP.flags%")
        print(f"{flags_description}: {count}")

