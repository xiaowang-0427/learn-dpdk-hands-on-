from scapy.all import *

# 构造以太网帧
eth = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
ip = IP(src="192.168.1.2", dst="192.168.1.1")
udp = UDP(sport=1234, dport=5678)
payload = "Hello, DPDK!"

# 组合数据包
pkt = eth / ip / udp / payload

# 发送数据包到 tap0
sendp(pkt, iface="tap0")