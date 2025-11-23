import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.animation as animation
from collections import deque
import time
import threading
import json
import socket

# 中文支持
plt.rcParams['font.sans-serif'] = ['SimHei']
plt.rcParams['axes.unicode_minus'] = False

# 配置地址 - 对应 config.h 中的网卡 IP 地址
MONITOR_SERVER_IP = "127.0.0.1"
MONITOR_SERVER_PORT = 9999

class ProtocolMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("协议栈可视化监控工具")
        self.root.geometry("1400x900")
        
        # 数据存储 (保存最近50个数据点)
        self.time_data = deque(maxlen=50)
        self.ip_packets_sent = deque(maxlen=50)
        self.ip_packets_received = deque(maxlen=50)
        self.tcp_packets_sent = deque(maxlen=50)
        self.tcp_packets_received = deque(maxlen=50)
        self.udp_packets_sent = deque(maxlen=50)
        self.udp_packets_received = deque(maxlen=50)
        self.icmp_packets_sent = deque(maxlen=50)
        self.icmp_packets_received = deque(maxlen=50)
        self.ethernet_packets_sent = deque(maxlen=50)
        self.ethernet_packets_received = deque(maxlen=50)
        
        # Socket连接
        self.sock = None
        self.connected = False
        self.sock_lock = threading.Lock()
        self.recv_buffer = b''  # 接收缓冲区，用于处理分片数据
        
        # 上一次的数据，用于计算增量
        self.last_stats = {}
        
        # 初始化数据
        self.init_data()
        
        # 创建界面
        self.create_widgets()
        
        # 启动数据更新线程
        self.update_thread = threading.Thread(target=self.update_data_thread, daemon=True)
        self.update_thread.start()
        
        # 在窗口加载完成后自动连接
        self.root.after(500, self.auto_connect)
        
    def init_data(self):
        """初始化数据"""
        current_time = time.time()
        for i in range(50):
            t = current_time - (50 - i) * 0.5
            self.time_data.append(t)
            self.ip_packets_sent.append(0)
            self.ip_packets_received.append(0)
            self.tcp_packets_sent.append(0)
            self.tcp_packets_received.append(0)
            self.udp_packets_sent.append(0)
            self.udp_packets_received.append(0)
            self.icmp_packets_sent.append(0)
            self.icmp_packets_received.append(0)
            self.ethernet_packets_sent.append(0)
            self.ethernet_packets_received.append(0)
    
    def create_widgets(self):
        """创建界面组件"""
        # 创建连接框架
        connect_frame = ttk.Frame(self.root)
        connect_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(connect_frame, text="服务器地址:", font=("Arial", 10)).pack(side="left")
        self.host_entry = ttk.Entry(connect_frame, width=15)
        self.host_entry.insert(0, MONITOR_SERVER_IP)
        self.host_entry.pack(side="left", padx=5)
        
        ttk.Label(connect_frame, text="端口:", font=("Arial", 10)).pack(side="left")
        self.port_entry = ttk.Entry(connect_frame, width=8)
        self.port_entry.insert(0, str(MONITOR_SERVER_PORT))
        self.port_entry.pack(side="left", padx=5)
        
        self.connect_button = ttk.Button(connect_frame, text="连接", command=self.toggle_connection)
        self.connect_button.pack(side="left", padx=5)
        
        self.status_label = ttk.Label(connect_frame, text="未连接", foreground="red", font=("Arial", 10, "bold"))
        self.status_label.pack(side="left", padx=10)
        
        # 创建标签页
        tab_control = ttk.Notebook(self.root)
        
        # 主监控页
        self.monitor_tab = ttk.Frame(tab_control)
        tab_control.add(self.monitor_tab, text="实时监控")
        
        # 统计信息页
        self.stats_tab = ttk.Frame(tab_control)
        tab_control.add(self.stats_tab, text="统计信息")
        
        tab_control.pack(expand=1, fill="both", padx=10, pady=10)
        
        # 构建监控页
        self.build_monitor_tab()
        
        # 构建统计信息页
        self.build_stats_tab()
        
    def toggle_connection(self):
        """切换连接状态"""
        if self.connected:
            self.disconnect()
        else:
            self.connect()
    
    def auto_connect(self):
        """自动连接到监控服务器"""
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())
            
            with self.sock_lock:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((host, port))
                self.connected = True
            
            self.connect_button.config(text="断开")
            self.status_label.config(text=f"已连接到 {host}:{port}", foreground="green")
            print(f"[INFO] Auto-connected to {host}:{port}")
            
        except Exception as e:
            print(f"[ERROR] Auto-connect failed: {str(e)}")
            # 不影响 UI，继续允许手动连接
            
    def connect(self):
        """连接到监控服务器"""
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())
            
            with self.sock_lock:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((host, port))
                self.connected = True
            
            self.connect_button.config(text="断开")
            self.status_label.config(text=f"已连接到 {host}:{port}", foreground="green")
            
        except Exception as e:
            self.status_label.config(text=f"连接失败: {str(e)}", foreground="red")
            self.connected = False
    def disconnect(self):
        """断开连接"""
        with self.sock_lock:
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass
                self.sock = None
            self.recv_buffer = b''  # 重置接收缓冲区
            
        self.connected = False
        self.connect_button.config(text="连接")
        self.status_label.config(text="未连接", foreground="red")
        
    def build_monitor_tab(self):
        """构建监控页"""
        # 创建图形框架
        graph_frame = ttk.Frame(self.monitor_tab)
        graph_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 创建matplotlib图形
        self.fig, self.axs = plt.subplots(2, 3, figsize=(14, 9))
        self.fig.tight_layout(pad=3.0)
        
        # 嵌入到tkinter中
        canvas = FigureCanvasTkAgg(self.fig, graph_frame)
        canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # 初始化图形
        self.update_graphs()
        
        # 启动图形更新动画
        self.ani = animation.FuncAnimation(self.fig, self.update_graphs, interval=1000, blit=False, cache_frame_data=False)
        
    def build_stats_tab(self):
        """构建统计信息页"""
        # 创建统计信息框架
        stats_frame = ttk.Frame(self.stats_tab)
        stats_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 以太网统计
        eth_frame = ttk.LabelFrame(stats_frame, text="以太网层统计", padding=10)
        eth_frame.pack(fill="x", padx=5, pady=5)
        self.ethernet_stats_label = ttk.Label(eth_frame, text="发送: 0 包, 0 字节\n接收: 0 包, 0 字节\n错误: 0", 
                                              font=("Courier", 9))
        self.ethernet_stats_label.pack(padx=5, pady=5)
        
        # IP统计信息
        ip_frame = ttk.LabelFrame(stats_frame, text="IP层统计", padding=10)
        ip_frame.pack(fill="x", padx=5, pady=5)
        self.ip_stats_label = ttk.Label(ip_frame, text="发送: 0 包, 0 字节\n接收: 0 包, 0 字节\n错误: 0", 
                                        font=("Courier", 9))
        self.ip_stats_label.pack(padx=5, pady=5)
        
        # TCP统计信息
        tcp_frame = ttk.LabelFrame(stats_frame, text="TCP层统计", padding=10)
        tcp_frame.pack(fill="x", padx=5, pady=5)
        self.tcp_stats_label = ttk.Label(tcp_frame, text="发送: 0 包, 0 字节\n接收: 0 包, 0 字节\n错误: 0", 
                                         font=("Courier", 9))
        self.tcp_stats_label.pack(padx=5, pady=5)
        
        # UDP统计信息
        udp_frame = ttk.LabelFrame(stats_frame, text="UDP层统计", padding=10)
        udp_frame.pack(fill="x", padx=5, pady=5)
        self.udp_stats_label = ttk.Label(udp_frame, text="发送: 0 包, 0 字节\n接收: 0 包, 0 字节\n错误: 0", 
                                         font=("Courier", 9))
        self.udp_stats_label.pack(padx=5, pady=5)
        
        # ICMP统计信息
        icmp_frame = ttk.LabelFrame(stats_frame, text="ICMP层统计", padding=10)
        icmp_frame.pack(fill="x", padx=5, pady=5)
        self.icmp_stats_label = ttk.Label(icmp_frame, text="发送: 0 包, 0 字节\n接收: 0 包, 0 字节\n错误: 0", 
                                          font=("Courier", 9))
        self.icmp_stats_label.pack(padx=5, pady=5)
        
    def update_graphs(self, frame=None):
        """更新图形"""
        # 清除所有子图
        for ax in self.axs.flat:
            ax.clear()
            
        # 转换时间为相对时间（秒）
        if len(self.time_data) > 0:
            relative_times = [t - self.time_data[0] for t in self.time_data]
        else:
            relative_times = []
        
        # IP数据包图表
        self.axs[0, 0].plot(relative_times, list(self.ip_packets_sent), 'r-', label='发送', linewidth=2)
        self.axs[0, 0].plot(relative_times, list(self.ip_packets_received), 'g-', label='接收', linewidth=2)
        self.axs[0, 0].set_title('IP数据包', fontsize=12, fontweight='bold')
        self.axs[0, 0].legend(loc='upper left')
        self.axs[0, 0].set_ylabel('数据包数量')
        self.axs[0, 0].grid(True, alpha=0.3)
        
        # TCP数据包图表
        self.axs[0, 1].plot(relative_times, list(self.tcp_packets_sent), 'r-', label='发送', linewidth=2)
        self.axs[0, 1].plot(relative_times, list(self.tcp_packets_received), 'g-', label='接收', linewidth=2)
        self.axs[0, 1].set_title('TCP数据包', fontsize=12, fontweight='bold')
        self.axs[0, 1].legend(loc='upper left')
        self.axs[0, 1].set_ylabel('数据包数量')
        self.axs[0, 1].grid(True, alpha=0.3)
        
        # UDP数据包图表
        self.axs[0, 2].plot(relative_times, list(self.udp_packets_sent), 'r-', label='发送', linewidth=2)
        self.axs[0, 2].plot(relative_times, list(self.udp_packets_received), 'g-', label='接收', linewidth=2)
        self.axs[0, 2].set_title('UDP数据包', fontsize=12, fontweight='bold')
        self.axs[0, 2].legend(loc='upper left')
        self.axs[0, 2].set_ylabel('数据包数量')
        self.axs[0, 2].grid(True, alpha=0.3)
        
        # ICMP数据包图表
        self.axs[1, 0].plot(relative_times, list(self.icmp_packets_sent), 'r-', label='发送', linewidth=2)
        self.axs[1, 0].plot(relative_times, list(self.icmp_packets_received), 'g-', label='接收', linewidth=2)
        self.axs[1, 0].set_title('ICMP数据包', fontsize=12, fontweight='bold')
        self.axs[1, 0].legend(loc='upper left')
        self.axs[1, 0].set_xlabel('时间 (秒)')
        self.axs[1, 0].set_ylabel('数据包数量')
        self.axs[1, 0].grid(True, alpha=0.3)
        
        # 以太网数据包图表
        self.axs[1, 1].plot(relative_times, list(self.ethernet_packets_sent), 'r-', label='发送', linewidth=2)
        self.axs[1, 1].plot(relative_times, list(self.ethernet_packets_received), 'g-', label='接收', linewidth=2)
        self.axs[1, 1].set_title('以太网数据包', fontsize=12, fontweight='bold')
        self.axs[1, 1].legend(loc='upper left')
        self.axs[1, 1].set_xlabel('时间 (秒)')
        self.axs[1, 1].set_ylabel('数据包数量')
        self.axs[1, 1].grid(True, alpha=0.3)
        
        # 协议占比饼图
        if self.last_stats:
            protocols = ['IP', 'TCP', 'UDP', 'ICMP']
            packets = [
                self.last_stats.get('ip', {}).get('packets_received', 0),
                self.last_stats.get('tcp', {}).get('packets_received', 0),
                self.last_stats.get('udp', {}).get('packets_received', 0),
                self.last_stats.get('icmp', {}).get('packets_received', 0)
            ]
            total = sum(packets)
            if total > 0:
                self.axs[1, 2].pie(packets, labels=protocols, autopct='%1.1f%%', startangle=90)
            self.axs[1, 2].set_title('接收数据包分布', fontsize=12, fontweight='bold')
        
        self.fig.canvas.draw_idle()
        
    def update_stats_display(self):
        """更新统计信息显示"""
        if not self.last_stats:
            return
        
        # 以太网统计
        eth_stats = self.last_stats.get('ethernet', {})
        self.ethernet_stats_label.config(
            text=f"发送: {eth_stats.get('packets_sent', 0)} 包, {eth_stats.get('bytes_sent', 0)} 字节\n"
                 f"接收: {eth_stats.get('packets_received', 0)} 包, {eth_stats.get('bytes_received', 0)} 字节\n"
                 f"错误: {eth_stats.get('errors', 0)}"
        )
        
        # IP统计
        ip_stats = self.last_stats.get('ip', {})
        self.ip_stats_label.config(
            text=f"发送: {ip_stats.get('packets_sent', 0)} 包, {ip_stats.get('bytes_sent', 0)} 字节\n"
                 f"接收: {ip_stats.get('packets_received', 0)} 包, {ip_stats.get('bytes_received', 0)} 字节\n"
                 f"错误: {ip_stats.get('errors', 0)}"
        )
        
        # TCP统计
        tcp_stats = self.last_stats.get('tcp', {})
        self.tcp_stats_label.config(
            text=f"发送: {tcp_stats.get('packets_sent', 0)} 包, {tcp_stats.get('bytes_sent', 0)} 字节\n"
                 f"接收: {tcp_stats.get('packets_received', 0)} 包, {tcp_stats.get('bytes_received', 0)} 字节\n"
                 f"错误: {tcp_stats.get('errors', 0)}"
        )
        
        # UDP统计
        udp_stats = self.last_stats.get('udp', {})
        self.udp_stats_label.config(
            text=f"发送: {udp_stats.get('packets_sent', 0)} 包, {udp_stats.get('bytes_sent', 0)} 字节\n"
                 f"接收: {udp_stats.get('packets_received', 0)} 包, {udp_stats.get('bytes_received', 0)} 字节\n"
                 f"错误: {udp_stats.get('errors', 0)}"
        )
        
        # ICMP统计
        icmp_stats = self.last_stats.get('icmp', {})
        self.icmp_stats_label.config(
            text=f"发送: {icmp_stats.get('packets_sent', 0)} 包, {icmp_stats.get('bytes_sent', 0)} 字节\n"
                 f"接收: {icmp_stats.get('packets_received', 0)} 包, {icmp_stats.get('bytes_received', 0)} 字节\n"
                 f"错误: {icmp_stats.get('errors', 0)}"
        )
        
    def update_data_thread(self):
        """数据更新线程"""
        while True:
            # 获取当前时间
            current_time = time.time()
            
            # 如果未连接，等待后继续
            if not self.connected or not self.sock:
                time.sleep(1)
                continue
                
            try:
                # 请求统计数据
                with self.sock_lock:
                    if self.sock and self.connected:
                        self.sock.sendall(b"GET_STATS\n")
                        # 接收数据直到遇到换行符
                        while b'\n' not in self.recv_buffer:
                            chunk = self.sock.recv(4096)
                            if not chunk:
                                raise ConnectionError("Connection closed by server")
                            self.recv_buffer += chunk
                        
                        # 提取一行数据
                        line_end = self.recv_buffer.find(b'\n')
                        response = self.recv_buffer[:line_end]
                        self.recv_buffer = self.recv_buffer[line_end + 1:]
                    else:
                        time.sleep(1)
                        continue
                
                if not response:
                    self.connected = False
                    self.root.after(0, lambda: self.status_label.config(text="连接已断开", foreground="red"))
                    continue
                
                # 解析JSON数据
                try:
                    json_str = response.decode('utf-8')
                    stats = json.loads(json_str)
                except json.JSONDecodeError as e:
                    print(f"[ERROR] JSON parsing failed: {str(e)}")
                    print(f"[DEBUG] Raw data: {response}")
                    self.root.after(0, lambda: self.status_label.config(text=f"数据格式错误", foreground="red"))
                    time.sleep(1)
                    continue
                
                self.last_stats = stats
                
                # 添加新数据点
                self.time_data.append(current_time)
                
                # 提取各协议的数据包计数（取增量）
                ip_stats = stats.get('ip', {})
                tcp_stats = stats.get('tcp', {})
                udp_stats = stats.get('udp', {})
                icmp_stats = stats.get('icmp', {})
                ethernet_stats = stats.get('ethernet', {})
                
                self.ip_packets_sent.append(ip_stats.get('packets_sent', 0))
                self.ip_packets_received.append(ip_stats.get('packets_received', 0))
                self.tcp_packets_sent.append(tcp_stats.get('packets_sent', 0))
                self.tcp_packets_received.append(tcp_stats.get('packets_received', 0))
                self.udp_packets_sent.append(udp_stats.get('packets_sent', 0))
                self.udp_packets_received.append(udp_stats.get('packets_received', 0))
                self.icmp_packets_sent.append(icmp_stats.get('packets_sent', 0))
                self.icmp_packets_received.append(icmp_stats.get('packets_received', 0))
                self.ethernet_packets_sent.append(ethernet_stats.get('packets_sent', 0))
                self.ethernet_packets_received.append(ethernet_stats.get('packets_received', 0))
                
                # 更新UI组件
                self.root.after(0, self.update_stats_display)
                
            except ConnectionResetError:
                self.connected = False
                self.recv_buffer = b''
                self.root.after(0, lambda: self.status_label.config(text="连接已被重置", foreground="red"))
                print("[ERROR] Connection reset by peer")
                time.sleep(1)
            except ConnectionError as e:
                self.connected = False
                self.recv_buffer = b''
                self.root.after(0, lambda: self.status_label.config(text="连接已断开", foreground="red"))
                print(f"[ERROR] Connection error: {str(e)}")
                time.sleep(1)
            except Exception as e:
                print(f"[ERROR] Update failed: {str(e)}")
                time.sleep(1)
                if "未连接" not in str(e):
                    self.root.after(0, lambda: self.status_label.config(text=f"错误: {type(e).__name__}", foreground="red"))
                
            # 等待1秒
            time.sleep(1)

def main():
    root = tk.Tk()
    app = ProtocolMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()