import unittest
from scapy.all import IP, TCP, Ether
from src.analyze import analyze_packets  # 确保这里的导入路径与你的项目结构相匹配

class TestPacketAnalysis(unittest.TestCase):
    def setUp(self):
        # 这个方法在每个测试方法执行前执行，可以用来设置测试环境
        self.packets = [
            Ether()/IP(dst="192.168.0.1", src="192.168.0.2")/TCP(dport=80, flags='S'),
            Ether()/IP(dst="192.168.0.2", src="192.168.0.1")/TCP(dport=8080, flags='A'),
            Ether()/IP(dst="192.168.0.1", src="192.168.0.3")/TCP(dport=10000, flags='S')
        ]

    def test_packet_statistics(self):
        # 实际的测试方法，确保它以 'test' 开头
        result = analyze_packets(self.packets)  # 这假设你的 analyze_packets 函数返回一些可用于断言的统计数据
        # 进行断言测试
        self.assertIn("TCP", result['protocols'])  # 确保TCP是被统计的协议之一
        self.assertEqual(result['ip_dst']['192.168.0.1'], 2)  # 检查192.168.0.1作为目的地的包数量
        self.assertEqual(result['tcp_flags']['S'], 2)  # 检查SYN标志的数量

# 如果这个文件被直接运行，那么执行测试
if __name__ == '__main__':
    unittest.main()
