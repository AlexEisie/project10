import sys
import time
from scapy.all import *
from collections import defaultdict
from optparse import OptionParser
import os
import re

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
def capture_traffic(interface="mirror-eth0", capture_duration=None):
    print(f"开始捕获流量 on {interface}...")
    start_time = time.time()
    
    try:
        while True:
            sniff(iface=interface, prn=packet_callback, store=0, timeout=1)
            print_traffic()  # 每秒刷新一次显示
            time.sleep(1)  # 控制刷新频率
            
            # 如果设置了捕获时长，检查是否到达捕获时长
            if capture_duration and time.time() - start_time >= capture_duration:
                print("\n捕获时间已结束。")
                break
                
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

# 时间格式解析函数（解析捕获时间）
def parse_duration(duration_str):
    # 匹配时间格式（例如：10s，1m9s，8d5h3m）
    pattern = re.compile(r'(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?')
    match = pattern.match(duration_str)
    if not match:
        raise ValueError(f"无效的时间格式: {duration_str}")

    days = int(match.group(1) or 0)
    hours = int(match.group(2) or 0)
    minutes = int(match.group(3) or 0)
    seconds = int(match.group(4) or 0)

    # 转换为总秒数
    total_seconds = days * 86400 + hours * 3600 + minutes * 60 + seconds
    return total_seconds

# 主函数
if __name__ == "__main__":
    # 设置命令行参数
    parser = OptionParser()
    parser.add_option("-I", "--interface", dest="interface", default="mirror-eth0", 
                      help="指定监听的网络接口，默认 'mirror-eth0'")
    parser.add_option("-t", "--time", dest="capture_time", default=None, 
                      help="指定捕获时间（例如：10s，1m9s，8d5h3m）。默认不设置则一直运行。")

    (options, args) = parser.parse_args()

    # 如果指定了捕获时间，解析时间参数
    capture_duration = None
    if options.capture_time:
        try:
            capture_duration = parse_duration(options.capture_time)
            print(f"捕获时间为 {capture_duration} 秒")
        except ValueError as e:
            print(e)
            sys.exit(1)
    
    # 捕获流量并显示
    capture_traffic(interface=options.interface, capture_duration=capture_duration)
