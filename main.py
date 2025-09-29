import sys
import time
from scapy.all import *
from collections import defaultdict
from optparse import OptionParser
import os

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

# 实时打印目标IP及其流量（默认显示前20个）
def print_traffic():
    os.system('clear')  # 清屏
    print(f"{'目标IP':<20} {'流量大小 (字节)'}")
    print("-" * 40)
    
    # 排序并输出前20个目标IP
    sorted_ips = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:20]
    for ip, traffic in sorted_ips:
        print(f"{ip:<20} {traffic}")

# 捕获网络流量并实时更新
def capture_traffic(interface="mirror-eth0"):
    print(f"开始捕获流量 on {interface}...")
    try:
        while True:
            sniff(iface=interface, prn=packet_callback, store=0, timeout=1)
            print_traffic()  # 每秒刷新一次显示
            time.sleep(1)  # 控制刷新频率
    except KeyboardInterrupt:
        print("\n捕获停止。")
        save_traffic_to_file()  # 退出时保存数据到文件

# 将流量数据保存到文件
def save_traffic_to_file(filename="traffic_data.txt"):
    with open(filename, "w") as file:
        file.write(f"{'目标IP':<20} {'流量大小 (字节)'}\n")
        file.write("-" * 40 + "\n")
        sorted_ips = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)
        for ip, traffic in sorted_ips:
            file.write(f"{ip:<20} {traffic}\n")
    print(f"数据已保存到 {filename}")

# 主函数
if __name__ == "__main__":
    # 设置命令行参数
    parser = OptionParser()
    parser.add_option("-i", "--interface", dest="interface", default="mirror-eth0", 
                      help="指定监听的网络接口，默认 'mirror-eth0'")
    
    (options, args) = parser.parse_args()
    
    # 捕获流量并显示
    capture_traffic(interface=options.interface)
