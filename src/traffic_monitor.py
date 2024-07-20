from collections import deque
import time

class TrafficMonitor:
    def __init__(self, window_size=10, threshold=50):
        # Initialize a deque to store packet counts per second
        self.packet_count = deque(maxlen=window_size)
        # Threshold for triggering an anomaly alert
        self.threshold = threshold

    def process_packet(self, packet):
        # Track packets per second
        current_time = int(time.time())
        if not self.packet_count or self.packet_count[-1][0] != current_time:
            self.packet_count.append([current_time, 1])
        else:
            self.packet_count[-1][1] += 1
        
        # Detect anomalies based on the defined threshold
        self.detect_anomaly()

    def detect_anomaly(self):
        # Sum packet counts and check against the threshold
        if sum(count for _, count in self.packet_count) > self.threshold:
            print("Traffic anomaly detected! Possible DDoS attack.")
        
    def reset(self):
        self.packet_count.clear()  # Clear all recorded packet counts
        # 如果有其他状态需要重置，也应在这里处理

