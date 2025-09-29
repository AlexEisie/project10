from scapy.all import *
from collections import defaultdict

# 用于存储目标IP和其对应的流量大小
ip_traffic = defaultdict(int)

# 定义回调函数，用于处理每个捕获的数据包
def packet_callback(packet):
    if IP in packet:
        # 获取目标IP地址
        dst_ip = packet[IP].dst
        # 获取数据包的大小
        packet_size = len(packet)
        # 累加目标IP的流量
        ip_traffic[dst_ip] += packet_size

# 开始捕获网络流量，过滤出IP包
def capture_traffic(interface="eth0"):
    print(f"开始捕获流量 on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

# 排序并打印目的IP及其流量
def sort_and_print_traffic():
    # 按照流量大小排序
    sorted_ips = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)
    
    print("\n流量目的地 IP 排序：")
    print(f"{'目标IP':<20} {'流量大小 (字节)'}")
    print("-" * 40)
    
    for ip, traffic in sorted_ips:
        print(f"{ip:<20} {traffic}")

# 主函数
if __name__ == "__main__":
    # 捕获流量
    capture_traffic(interface="mirror-eth0")  # 根据你的网卡名称修改 'eth0'

    # 排序并打印结果
    sort_and_print_traffic()
