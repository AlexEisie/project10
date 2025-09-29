import sys
import time
from scapy.all import *
from collections import defaultdict
from optparse import OptionParser
import os
import keyboard

# 用于存储目标IP和其对应的流量大小
ip_traffic = defaultdict(int)

# 当前展示的数量，默认为前十个
display_count = 10

# 定义回调函数，用于处理每个捕获的数据包
def packet_callback(packet):
    if IP in packet:
        # 获取目标IP地址
        dst_ip = packet[IP].dst
        # 获取数据包的大小
        packet_size = len(packet)
        # 累加目标IP的流量
        ip_traffic[dst_ip] += packet_size

# 实时打印目标IP及其流量
def print_traffic():
    os.system('clear')  # 清屏
    print(f"{'目标IP':<20} {'流量大小 (字节)'}")
    print("-" * 40)
    
    # 排序并输出
    sorted_ips = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)
    
    # 根据当前展示的数量显示流量
    for ip, traffic in sorted_ips[:display_count]:
        print(f"{ip:<20} {traffic}")
    
    # 提示用户按下 'A' 展开/折叠
    print("\n按 'A' 展开/折叠显示更多 IP，按 'Ctrl+C' 退出并生成报告。")

# 捕获网络流量并实时更新
def capture_traffic(interface="mirror-eth0"):
    global display_count
    print(f"开始捕获流量 on {interface}...")
    try:
        while True:
            sniff(iface=interface, prn=packet_callback, store=0, timeout=1)
            print_traffic()  # 每秒刷新一次显示

            # 如果用户按下 'A'，切换展示更多或折叠
            if keyboard.is_pressed('a'):
                display_count = len(ip_traffic) if display_count == 10 else 10
                time.sleep(0.5)  # 防止多次触发

            time.sleep(1)  # 控制刷新频率
    except KeyboardInterrupt:
        print("\n捕获停止。")
        generate_report()  # 生成报告

# 生成报告文件
def generate_report():
    sorted_ips = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)
    
    # 创建报告文件
    with open("traffic_report.txt", "w") as report_file:
        report_file.write("流量目的地 IP 排序报告\n")
        report_file.write(f"{'目标IP':<20} {'流量大小 (字节)'}\n")
        report_file.write("-" * 40 + "\n")
        
        for ip, traffic in sorted_ips:
            report_file.write(f"{ip:<20} {traffic}\n")
    
    print("报告已生成：traffic_report.txt")

# 主函数
if __name__ == "__main__":
    # 设置命令行参数
    parser = OptionParser()
    parser.add_option("-i", "--interface", dest="interface", default="mirror-eth0", 
                      help="指定监听的网络接口，默认 'mirror-eth0'")
    
    (options, args) = parser.parse_args()
    
    # 捕获流量并显示
    capture_traffic(interface=options.interface)
