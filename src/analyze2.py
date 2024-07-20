import sys
from collections import Counter
from scapy.all import IP, TCP, sniff

def analyze_packets(packets):
    """
    Analyze captured packets.
    :param packets: a list of packets to analyze.
    :return: A dictionary containing analysis results.
    """
    # ip_src = Counter()
    # non_standard_ports = Counter()  # 非标准端口通常指不常用的高端口
    # large_packets = Counter()

    # for packet in packets:
    #     if IP in packet:
    #         ip_src[packet[IP].src] += 1
    #         if packet[IP].len > 1400:  # 假设大型数据包定义为长度大于1400字节
    #             large_packets[packet[IP].src] += 1
    #         if TCP in packet and packet[TCP].dport >= 1024:  # 监测非标准端口
    #             non_standard_ports[packet[IP].src] += 1

    # alerts = []
    # # 检测异常行为
    # for ip, count in ip_src.items():
    #     if count > 100:  # 阈值为100
    #         alerts.append(f"高请求量警告: IP {ip} 发送了 {count} 个请求")
    # for ip, count in non_standard_ports.items():
    #     if count > 50:  # 阈值为50
    #         alerts.append(f"非常规端口使用警告: IP {ip} 在非标准端口上的请求次数为 {count}")
    # for ip, count in large_packets.items():
    #     if count > 10:  # 阈值为10
    #         alerts.append(f"大型数据包警告: IP {ip} 发送了 {count} 个大型数据包")

    # return alerts
    # data = {
    #     'source_ip': [],
    #     'destination_ip': [],
    #     'protocol': [],
    #     'length': [],
    #     'tcp_flags': []
    # }

    # protocols = Counter()  # 统计各种协议的使用
    # tcp_flags = Counter()  # 统计TCP标志位的使用
    # ip_src = Counter()  # 统计源IP地址
    # ip_dst = Counter()  # 统计目的IP地址
    # protocol_layers = Counter()  # 统计协议层次结构
    # layer_sequences = Counter()  # 新增计数器来统计网络层序列
    # potential_scans = []  # 存储可能的扫描活动
    # large_packets = []  # 存储大型数据包信息

    # for packet in packets:
    #     # 统计协议和协议层次结构
    #     if IP in packets:
    #         data['source_ip'].append(packet[IP].src)
    #         data['destination_ip'].append(packet[IP].dst)
    #         data['protocol'].append(packet[IP].proto)
    #         data['length'].append(len(packet))
    #         ip_src[packet[IP].src] += 1
    #         ip_dst[packet[IP].dst] += 1

    #     if TCP in packet:
    #         flags = packet[TCP].flags
    #         data['tcp_flags'].append(flags)
    #         tcp_flags[flags] += 1

    #     layers = []
    #     layer = packet
    #     while layer:
    #         layer_name = layer.name
    #         if layer_name not in layers:
    #             layers.append(layer_name)
    #         protocols[layer_name] += 1
    #         layer = layer.payload
    #     protocol_layers[tuple(layers)] += 1
    #     layer_sequences[' -> '.join(layers)] += 1  # 新增：将层序列转为字符串

        # # 统计IP地址
        # if packet.haslayer(IP):
        #     ip_src[packet[IP].src] += 1
        #     ip_dst[packet[IP].dst] += 1

        # # 统计TCP标志位
        # if TCP in packet:
        #     flag = packet.sprintf("%TCP.flags%")
        #     tcp_flags[flag] += 1
        #     # 检测可能的扫描活动
        #     if packet[TCP].dport > 1024 and packet[TCP].flags == 'S':
        #         potential_scans.append(f"Scanning from {packet[IP].src} to {packet[IP].dst} on port {packet[TCP].dport}")

        # 检测大型数据包
        # if len(packet) > 1500:
        #     large_packets.append(f"Large packet from {packet[IP].src} to {packet[IP].dst}")

    protocols = Counter()
    tcp_flags = Counter()
    ip_src = Counter()
    ip_dst = Counter()
    protocol_layers = Counter()
    layer_sequences = Counter()

    for packet in packets:
        if IP in packet:  # 正确检查单个数据包是否含有IP层
            ip_src[packet[IP].src] += 1
            ip_dst[packet[IP].dst] += 1
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
        
        if TCP in packet:
            flag_str = packet[TCP].sprintf('%TCP.flags%')
            tcp_flags[flag_str] += 1

    return {
        'protocols': dict(protocols),
        'tcp_flags': dict(tcp_flags),
        'ip_src': dict(ip_src),
        'ip_dst': dict(ip_dst),
        'protocol_layers': dict(protocol_layers),
        'layer_sequences': dict(layer_sequences)
    }

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