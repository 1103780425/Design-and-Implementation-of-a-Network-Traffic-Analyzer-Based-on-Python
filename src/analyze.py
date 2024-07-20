import pandas as pd
import sys
from collections import Counter
from scapy.all import IP, TCP, sniff

def analyze_packets(packets):
    """
    Analyze captured packets.
    :param packets: a list of packets to analyze.
    :return: A dictionary containing analysis results.
    """
    ip_src = Counter()
    non_standard_ports = Counter()  # 非标准端口通常指不常用的高端口
    large_packets = Counter()

    protocols = Counter()
    tcp_flags = Counter()
    ip_src = Counter()
    ip_dst = Counter()
    protocol_layers = Counter()
    layer_sequences = Counter()

    alerts = []
    for packet in packets:
        if IP in packet:
            ip_src[packet[IP].src] += 1
            ip_dst[packet[IP].dst] += 1

            if packet[IP].len > 1400:
                large_packets[packet[IP].src] += 1

            layers = []
            layer = packet
            while layer:
                layer_name = layer.name
                if layer_name not in layers:
                    layers.append(layer_name)
                protocols[layer_name] += 1
                layer = layer.payload
            protocol_layers[tuple(layers)] += 1
            layer_sequences[' -> '.join(layers)] += 1
        else:
            continue

        if TCP in packet:
            tcp_flags[packet[TCP].sprintf('%TCP.flags%')] += 1
            if packet[TCP].dport >= 1024:
                non_standard_ports[packet[IP].src] += 1

    # Generate alerts based on thresholds
    for ip, count in ip_src.items():
        if count > 100:
            alerts.append(f"High volume of requests from IP {ip}: {count} requests")
    for ip, count in non_standard_ports.items():
        if count > 50:
            alerts.append(f"Unusual port usage from IP {ip}: {count} times on non-standard ports")
    for ip, count in large_packets.items():
        if count > 10:
            alerts.append(f"Large packet transmission from IP {ip}: {count} large packets")

    # Prepare the standard data report
    results = {
        'protocols': dict(protocols),
        'tcp_flags': dict(tcp_flags),
        'ip_src': dict(ip_src),
        'ip_dst': dict(ip_dst),
        'protocol_layers': dict(protocol_layers),
        'layer_sequences': dict(layer_sequences)
    }

    # Return both alerts and results
    return alerts, results

    # return {
    #     'protocols': dict(protocols),
    #     'tcp_flags': dict(tcp_flags),
    #     'ip_src': dict(ip_src),
    #     'ip_dst': dict(ip_dst),
    #     'protocol_layers': dict(protocol_layers),
    #     'layer_sequences': dict(layer_sequences),  # 新增：返回网络层序列的统计结果
    #     'potential_scans': potential_scans,
    #     'large_packets': large_packets
    # }

def capture_and_analyze(interface, count):
    """
    Capture packets and analyze them.
    """
    try:
        packets = sniff(iface=interface, count=count)
        results = analyze_packets(packets)
        print("Analysis Results:", results)
    except Exception as e:
        sys.stderr.write(f"Error capturing or analyzing packets: {str(e)}\n")

if __name__ == "__main__":
    # Replace 'eth0' with your actual network interface
    capture_and_analyze('Intel(R) Ethernet Connection (12) I219-V', 10)

####

# import pandas as pd
# import sys
# from collections import Counter
# from scapy.all import IP, TCP, sniff

# def analyze_packets(packets):
#     protocols = Counter()
#     tcp_flags = Counter()
#     ip_src = Counter()
#     ip_dst = Counter()
#     protocol_layers = Counter()
#     layer_sequences = Counter()

#     for packet in packets:
#         if IP in packet:
#             ip_src[packet[IP].src] += 1
#             ip_dst[packet[IP].dst] += 1
        
#         if TCP in packet:
#             flags = packet[TCP].flags
#             flag_str = packet[TCP].sprintf('%TCP.flags%')  # 获取可读的标志位字符串
#             tcp_flags[flag_str] += 1
#             print(f"TCP Packet: SRC={packet[IP].src}, DST={packet[IP].dst}, Flags={flag_str}")

#         layers = []
#         layer = packet
#         while layer:
#             layer_name = layer.name
#             layers.append(layer_name)
#             protocols[layer_name] += 1
#             layer = layer.payload
#         protocol_layers[tuple(layers)] += 1
#         layer_sequences[' -> '.join(layers)] += 1

#     return {
#         'protocols': dict(protocols),
#         'tcp_flags': dict(tcp_flags),
#         'ip_src': dict(ip_src),
#         'ip_dst': dict(ip_dst),
#         'protocol_layers': dict(protocol_layers),
#         'layer_sequences': dict(layer_sequences)
#     }

# def capture_and_analyze(interface, count):
#     """
#     Capture packets and analyze them.
#     """
#     try:
#         packets = sniff(iface=interface, count=count)
#         results = analyze_packets(packets)
#         print("Analysis Results:", results)
#     except Exception as e:
#         sys.stderr.write(f"Error capturing or analyzing packets: {str(e)}\n")

# if __name__ == "__main__":
#     # Replace 'eth0' with your actual network interface
#     capture_and_analyze('Intel(R) Ethernet Connection (12) I219-V', 10)