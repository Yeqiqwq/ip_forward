#!/usr/bin/env python3
"""
BGP服务器转发脚本 - 简化版
功能：
1. 每5秒查询DNS获取目标服务器IP
2. 转发所有端口(1-65535)的TCP/UDP流量
3. 完整的性能监控和日志输出
4. 自动故障恢复和重试机制
"""

import socket
import subprocess
import time
import logging
import sys
import threading
import json
import os
import psutil
from typing import Optional, Dict, Any
from datetime import datetime
import signal

class PerformanceLogger:
    """性能日志记录器"""
    
    def __init__(self, log_interval: int = 30):
        self.log_interval = log_interval
        self.running = False
        self.connection_stats = {
            'total_connections': 0,
            'tcp_connections': 0,
            'udp_connections': 0,
            'established_connections': 0
        }
        
    def start_logging(self):
        """启动性能日志记录"""
        self.running = True
        log_thread = threading.Thread(target=self._log_loop)
        log_thread.daemon = True
        log_thread.start()
        logging.info("性能监控日志已启动")
    
    def stop_logging(self):
        """停止性能日志记录"""
        self.running = False
    
    def _log_loop(self):
        """性能日志循环"""
        while self.running:
            try:
                self._log_system_performance()
                self._log_network_statistics()
                self._log_iptables_statistics()
                time.sleep(self.log_interval)
            except Exception as e:
                logging.error(f"性能日志记录错误: {e}")
    
    def _log_system_performance(self):
        """记录系统性能"""
        try:
            # CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            
            # 内存使用情况
            memory = psutil.virtual_memory()
            memory_used_gb = (memory.total - memory.available) / (1024**3)
            memory_total_gb = memory.total / (1024**3)
            memory_percent = memory.percent
            
            # 磁盘IO
            disk_io = psutil.disk_io_counters()
            
            # 网络IO
            net_io = psutil.net_io_counters()
            
            # 系统负载
            load_avg = os.getloadavg()
            
            logging.info(f"[性能监控] CPU: {cpu_percent:.1f}%({cpu_count}核) | "
                        f"内存: {memory_used_gb:.1f}GB/{memory_total_gb:.1f}GB({memory_percent:.1f}%) | "
                        f"负载: {load_avg[0]:.2f},{load_avg[1]:.2f},{load_avg[2]:.2f}")
            
            if disk_io:
                logging.info(f"[磁盘IO] 读取: {disk_io.read_bytes/(1024**2):.1f}MB | "
                            f"写入: {disk_io.write_bytes/(1024**2):.1f}MB")
            
            if net_io:
                logging.info(f"[网络IO] 接收: {net_io.bytes_recv/(1024**2):.1f}MB | "
                            f"发送: {net_io.bytes_sent/(1024**2):.1f}MB | "
                            f"丢包: 接收{net_io.dropin} 发送{net_io.dropout}")
                            
        except Exception as e:
            logging.error(f"获取系统性能数据失败: {e}")
    
    def _log_network_statistics(self):
        """记录网络连接统计"""
        try:
            connections = psutil.net_connections()
            
            stats = {
                'total': len(connections),
                'tcp': 0,
                'udp': 0,
                'established': 0,
                'listen': 0,
                'time_wait': 0,
                'close_wait': 0,
                'syn_sent': 0,
                'syn_recv': 0
            }
            
            for conn in connections:
                if conn.type == socket.SOCK_STREAM:
                    stats['tcp'] += 1
                elif conn.type == socket.SOCK_DGRAM:
                    stats['udp'] += 1
                
                if hasattr(conn, 'status'):
                    status = conn.status.lower()
                    if 'established' in status:
                        stats['established'] += 1
                    elif 'listen' in status:
                        stats['listen'] += 1
                    elif 'time_wait' in status:
                        stats['time_wait'] += 1
                    elif 'close_wait' in status:
                        stats['close_wait'] += 1
                    elif 'syn_sent' in status:
                        stats['syn_sent'] += 1
                    elif 'syn_recv' in status:
                        stats['syn_recv'] += 1
            
            self.connection_stats = stats
            
            logging.info(f"[连接统计] 总连接: {stats['total']} | "
                        f"TCP: {stats['tcp']} | UDP: {stats['udp']} | "
                        f"已建立: {stats['established']} | 监听: {stats['listen']}")
            
            if stats['time_wait'] > 1000:
                logging.warning(f"TIME_WAIT连接过多: {stats['time_wait']}")
                
        except Exception as e:
            logging.error(f"获取网络统计失败: {e}")
    
    def _log_iptables_statistics(self):
        """记录iptables规则统计"""
        try:
            # 获取NAT表统计
            result = subprocess.run("iptables -t nat -L -n -v", 
                                   shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                total_packets = 0
                total_bytes = 0
                
                for line in lines:
                    if 'DNAT' in line or 'SNAT' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                packets = int(parts[0])
                                bytes_str = parts[1]
                                
                                # 解析字节数（可能包含K, M, G等单位）
                                if 'K' in bytes_str:
                                    bytes_val = float(bytes_str.replace('K', '')) * 1024
                                elif 'M' in bytes_str:
                                    bytes_val = float(bytes_str.replace('M', '')) * 1024 * 1024
                                elif 'G' in bytes_str:
                                    bytes_val = float(bytes_str.replace('G', '')) * 1024 * 1024 * 1024
                                else:
                                    bytes_val = float(bytes_str)
                                
                                total_packets += packets
                                total_bytes += bytes_val
                            except (ValueError, IndexError):
                                continue
                
                logging.info(f"[转发统计] 处理包数: {total_packets:,} | "
                            f"转发流量: {total_bytes/(1024**2):.1f}MB")
                            
        except Exception as e:
            logging.error(f"获取iptables统计失败: {e}")

class BGPForwarder:
    def __init__(self, config: Dict[str, Any]):
        """初始化转发服务"""
        self.domain = config['domain']
        self.dns_server = config.get('dns_server', '223.5.5.5')
        self.backup_dns_servers = config.get('backup_dns_servers', ['114.114.114.114', '8.8.8.8'])
        self.check_interval = config.get('check_interval', 5)
        self.timeout = config.get('timeout', 10)
        self.retry_attempts = config.get('retry_attempts', 3)
        self.chain_prefix = config.get('iptables_chain_prefix', 'BGP_FWD')
        
        self.current_target_ip = None
        self.running = False
        self.bgp_server_ip = self._get_local_ip()
        self.last_rule_update = None
        
        # 性能监控
        self.perf_logger = PerformanceLogger(config.get('log_interval', 30))
        
        # 错误计数器
        self.error_count = 0
        self.max_errors = config.get('max_errors', 10)
        
        self._log_startup_info()

    def _log_startup_info(self):
        """记录启动信息"""
        logging.info("=" * 60)
        logging.info("BGP转发服务启动")
        logging.info("=" * 60)
        logging.info(f"BGP服务器IP: {self.bgp_server_ip}")
        logging.info(f"目标域名: {self.domain}")
        logging.info(f"DNS服务器: {self.dns_server}")
        logging.info(f"备用DNS: {', '.join(self.backup_dns_servers)}")
        logging.info(f"检查间隔: {self.check_interval}秒")
        logging.info(f"转发策略: 全端口转发 (1-65535)")
        logging.info(f"支持协议: TCP, UDP")
        logging.info("=" * 60)

    def _get_local_ip(self) -> str:
        """获取本机IP地址"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception as e:
            logging.error(f"获取本机IP失败: {e}")
            return "0.0.0.0"

    def resolve_domain(self, dns_server: str = None) -> Optional[str]:
        """通过指定DNS服务器解析域名"""
        if dns_server is None:
            dns_server = self.dns_server
            
        start_time = time.time()
        try:
            cmd = f"nslookup {self.domain} {dns_server}"
            result = subprocess.run(cmd, shell=True, capture_output=True, 
                                  text=True, timeout=self.timeout)
            
            resolve_time = (time.time() - start_time) * 1000
            
            if result.returncode != 0:
                logging.warning(f"DNS解析失败 (服务器: {dns_server}, 耗时: {resolve_time:.1f}ms): {result.stderr.strip()}")
                return None
            
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Address:' in line and dns_server not in line:
                    ip = line.split('Address:')[1].strip()
                    socket.inet_aton(ip)  # 验证IP格式
                    logging.info(f"DNS解析成功: {self.domain} -> {ip} (服务器: {dns_server}, 耗时: {resolve_time:.1f}ms)")
                    return ip
                    
        except subprocess.TimeoutExpired:
            logging.warning(f"DNS查询超时 (服务器: {dns_server}, 超时: {self.timeout}s)")
        except Exception as e:
            logging.error(f"DNS解析异常 (服务器: {dns_server}): {e}")
            
        return None

    def resolve_domain_with_retry(self) -> Optional[str]:
        """带重试机制的域名解析"""
        # 尝试主DNS服务器
        for attempt in range(self.retry_attempts):
            ip = self.resolve_domain(self.dns_server)
            if ip:
                self.error_count = 0  # 重置错误计数
                return ip
            if attempt < self.retry_attempts - 1:
                logging.info(f"DNS解析重试 {attempt + 1}/{self.retry_attempts}")
                time.sleep(2)
        
        # 尝试备用DNS服务器
        for backup_dns in self.backup_dns_servers:
            logging.info(f"尝试备用DNS服务器: {backup_dns}")
            ip = self.resolve_domain(backup_dns)
            if ip:
                self.error_count = 0
                return ip
        
        self.error_count += 1
        logging.error(f"所有DNS服务器解析失败 (连续失败: {self.error_count})")
        return None

    def setup_system_optimizations(self):
        """设置系统优化参数"""
        try:
            # 启用IP转发
            subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", 
                         shell=True, check=True)
            
            # 调整连接跟踪表大小
            subprocess.run("echo 1048576 > /proc/sys/net/netfilter/nf_conntrack_max", 
                          shell=True, check=False)
            
            # 调整连接超时
            subprocess.run("echo 300 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established", 
                          shell=True, check=False)
            
            # 网络优化
            optimizations = [
                "net.core.rmem_max = 134217728",
                "net.core.wmem_max = 134217728", 
                "net.core.rmem_default = 65536",
                "net.core.wmem_default = 65536",
                "net.core.netdev_max_backlog = 5000",
                "net.ipv4.tcp_window_scaling = 1",
                "net.ipv4.tcp_timestamps = 1",
                "net.ipv4.tcp_sack = 1",
                "net.ipv4.tcp_congestion_control = bbr"
            ]
            
            for opt in optimizations:
                subprocess.run(f"sysctl -w {opt}", shell=True, check=False)
            
            logging.info("系统网络优化参数已应用")
            
        except Exception as e:
            logging.error(f"应用系统优化失败: {e}")

    def create_custom_chains(self):
        """创建自定义iptables链"""
        try:
            chains = [
                f"{self.chain_prefix}_PREROUTING",
                f"{self.chain_prefix}_POSTROUTING",
                f"{self.chain_prefix}_FORWARD"
            ]
            
            for chain in chains:
                # 创建链（如果不存在）
                result = subprocess.run(f"iptables -t nat -L {chain}", 
                                      shell=True, capture_output=True)
                if result.returncode != 0:
                    subprocess.run(f"iptables -t nat -N {chain}", shell=True, check=True)
                    logging.info(f"创建NAT链: {chain}")
                
                if "FORWARD" in chain:
                    result = subprocess.run(f"iptables -L {chain}", 
                                          shell=True, capture_output=True)
                    if result.returncode != 0:
                        subprocess.run(f"iptables -N {chain}", shell=True, check=True)
                        logging.info(f"创建FILTER链: {chain}")
            
            # 连接到主链（避免重复添加）
            for table, main_chain, custom_chain in [
                ("nat", "PREROUTING", f"{self.chain_prefix}_PREROUTING"),
                ("nat", "POSTROUTING", f"{self.chain_prefix}_POSTROUTING"),
                ("filter", "FORWARD", f"{self.chain_prefix}_FORWARD")
            ]:
                check_cmd = f"iptables -t {table} -C {main_chain} -j {custom_chain}" if table == "nat" else f"iptables -C {main_chain} -j {custom_chain}"
                result = subprocess.run(check_cmd, shell=True, capture_output=True)
                
                if result.returncode != 0:
                    add_cmd = f"iptables -t {table} -A {main_chain} -j {custom_chain}" if table == "nat" else f"iptables -A {main_chain} -j {custom_chain}"
                    subprocess.run(add_cmd, shell=True, check=True)
                    logging.info(f"添加跳转规则: {main_chain} -> {custom_chain}")
                          
        except Exception as e:
            logging.error(f"创建自定义链失败: {e}")
            raise

    def clear_existing_rules(self):
        """清除现有的转发规则"""
        try:
            chains = [
                f"{self.chain_prefix}_PREROUTING",
                f"{self.chain_prefix}_POSTROUTING", 
                f"{self.chain_prefix}_FORWARD"
            ]
            
            for chain in chains:
                if "FORWARD" in chain:
                    subprocess.run(f"iptables -F {chain}", shell=True, check=False)
                else:
                    subprocess.run(f"iptables -t nat -F {chain}", shell=True, check=False)
            
            logging.info("已清除现有转发规则")
        except Exception as e:
            logging.error(f"清除规则失败: {e}")

    def setup_forwarding_rules(self, target_ip: str):
        """设置全端口转发规则"""
        try:
            start_time = time.time()
            self.clear_existing_rules()
            
            # TCP全端口转发
            tcp_cmd = (f"iptables -t nat -A {self.chain_prefix}_PREROUTING "
                      f"-p tcp -j DNAT --to-destination {target_ip}")
            subprocess.run(tcp_cmd, shell=True, check=True)
            
            # UDP全端口转发
            udp_cmd = (f"iptables -t nat -A {self.chain_prefix}_PREROUTING "
                      f"-p udp -j DNAT --to-destination {target_ip}")
            subprocess.run(udp_cmd, shell=True, check=True)
            
            # 设置SNAT规则
            snat_cmd = (f"iptables -t nat -A {self.chain_prefix}_POSTROUTING "
                       f"-d {target_ip} -j SNAT --to-source {self.bgp_server_ip}")
            subprocess.run(snat_cmd, shell=True, check=True)
            
            # 允许转发
            forward_cmd = f"iptables -A {self.chain_prefix}_FORWARD -j ACCEPT"
            subprocess.run(forward_cmd, shell=True, check=True)
            
            setup_time = (time.time() - start_time) * 1000
            self.last_rule_update = datetime.now()
            
            logging.info(f"✓ 全端口转发规则已设置到 {target_ip} (耗时: {setup_time:.1f}ms)")
            logging.info(f"✓ TCP/UDP 1-65535端口转发已激活")
            
        except subprocess.CalledProcessError as e:
            logging.error(f"设置iptables规则失败: {e}")
            raise

    def remove_custom_chains(self):
        """移除自定义iptables链"""
        try:
            # 从主链中移除跳转规则
            for table, main_chain, custom_chain in [
                ("nat", "PREROUTING", f"{self.chain_prefix}_PREROUTING"),
                ("nat", "POSTROUTING", f"{self.chain_prefix}_POSTROUTING"),
                ("filter", "FORWARD", f"{self.chain_prefix}_FORWARD")
            ]:
                del_cmd = f"iptables -t {table} -D {main_chain} -j {custom_chain}" if table == "nat" else f"iptables -D {main_chain} -j {custom_chain}"
                subprocess.run(del_cmd, shell=True, check=False)
            
            self.clear_existing_rules()
            
            # 删除自定义链
            chains = [
                f"{self.chain_prefix}_PREROUTING",
                f"{self.chain_prefix}_POSTROUTING",
                f"{self.chain_prefix}_FORWARD"
            ]
            
            for chain in chains:
                if "FORWARD" in chain:
                    subprocess.run(f"iptables -X {chain}", shell=True, check=False)
                else:
                    subprocess.run(f"iptables -t nat -X {chain}", shell=True, check=False)
            
            logging.info("已移除自定义iptables链和规则")
        except Exception as e:
            logging.error(f"移除自定义链失败: {e}")

    def monitor_and_update(self):
        """监控DNS变化并更新转发规则"""
        self.running = True
        
        while self.running:
            try:
                # 检查错误计数
                if self.error_count >= self.max_errors:
                    logging.critical(f"连续失败次数过多 ({self.error_count})，服务暂停")
                    time.sleep(60)  # 暂停1分钟后重试
                    self.error_count = 0
                    continue
                
                new_ip = self.resolve_domain_with_retry()
                
                if new_ip is None:
                    logging.warning(f"DNS解析失败，将在{self.check_interval}秒后重试")
                elif new_ip != self.current_target_ip:
                    old_ip = self.current_target_ip or "无"
                    logging.info(f"🔄 检测到IP变化: {old_ip} -> {new_ip}")
                    
                    self.setup_forwarding_rules(new_ip)
                    self.current_target_ip = new_ip
                    
                    logging.info(f"✅ 转发规则已更新至: {new_ip}")
                else:
                    logging.debug(f"IP未变化，当前目标: {new_ip}")
                
            except Exception as e:
                self.error_count += 1
                logging.error(f"监控过程异常 (错误计数: {self.error_count}): {e}")
            
            time.sleep(self.check_interval)

    def start(self):
        """启动转发服务"""
        try:
            # 检查root权限
            if os.geteuid() != 0:
                logging.error("需要root权限来修改iptables规则")
                sys.exit(1)
            
            # 应用系统优化
            self.setup_system_optimizations()
            
            # 创建自定义链
            self.create_custom_chains()
            
            # 启动性能监控
            self.perf_logger.start_logging()
            
            # 启动监控线程
            monitor_thread = threading.Thread(target=self.monitor_and_update)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            logging.info("🚀 BGP转发服务已启动，按Ctrl+C停止")
            
            # 信号处理
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
                
        except Exception as e:
            logging.error(f"启动服务失败: {e}")
            sys.exit(1)

    def _signal_handler(self, signum, frame):
        """信号处理器"""
        logging.info(f"收到信号 {signum}，准备停止服务")
        self.stop()

    def stop(self):
        """停止转发服务"""
        logging.info("🛑 正在停止转发服务...")
        self.running = False
        
        # 停止性能监控
        self.perf_logger.stop_logging()
        
        # 移除转发规则
        self.remove_custom_chains()
        
        logging.info("✅ 转发服务已安全停止")
        sys.exit(0)

def setup_logging(log_file: str = '/var/log/bgp_forwarder.log', log_level: str = 'INFO'):
    """设置日志配置"""
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # 创建日志目录
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def create_default_config(config_path: str):
    """创建默认配置文件"""
    default_config = {
        "domain": "your-domain.com",
        "dns_server": "223.5.5.5",
        "backup_dns_servers": ["114.114.114.114", "8.8.8.8", "1.1.1.1"],
        "check_interval": 5,
        "timeout": 10,
        "retry_attempts": 3,
        "log_file": "/var/log/bgp_forwarder.log",
        "log_level": "INFO",
        "log_interval": 30,
        "iptables_chain_prefix": "BGP_FWD",
        "max_errors": 10
    }
    
    config_dir = os.path.dirname(config_path)
    if config_dir and not os.path.exists(config_dir):
        os.makedirs(config_dir, exist_ok=True)
    
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(default_config, f, indent=2, ensure_ascii=False)

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='BGP服务器转发脚本 - 简化版')
    parser.add_argument('-c', '--config', default='/etc/bgp_forwarder.json',
                       help='配置文件路径')
    parser.add_argument('--create-config', action='store_true',
                       help='创建默认配置文件并退出')
    parser.add_argument('--domain', help='覆盖配置文件中的域名设置')
    parser.add_argument('--check-system', action='store_true',
                       help='检查系统配置并给出建议')
    
    args = parser.parse_args()
    
    # 系统检查
    if args.check_system:
        print("=== 系统配置检查 ===")
        print(f"CPU核心数: {psutil.cpu_count()}")
        memory = psutil.virtual_memory()
        print(f"总内存: {memory.total / (1024**3):.1f} GB")
        print(f"可用内存: {memory.available / (1024**3):.1f} GB")
        
        # 检查连接跟踪
        try:
            with open('/proc/sys/net/netfilter/nf_conntrack_max', 'r') as f:
                print(f"连接跟踪表大小: {f.read().strip()}")
        except:
            print("连接跟踪表大小: 未知")
        
        print("\n建议:")
        print("✓ 使用全端口转发可能产生大量连接")
        print("✓ 建议监控系统资源使用情况") 
        print("✓ 确保有足够的内存和CPU资源")
        sys.exit(0)
    
    # 创建配置文件
    if args.create_config:
        create_default_config(args.config)
        print(f"已创建默认配置文件: {args.config}")
        print("请编辑配置文件设置正确的域名")
        sys.exit(0)
    
    # 加载配置
    try:
        if not os.path.exists(args.config):
            print(f"配置文件不存在: {args.config}")
            print("使用 --create-config 创建默认配置文件")
            sys.exit(1)
            
        with open(args.config, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except Exception as e:
        print(f"加载配置文件失败: {e}")
        sys.exit(1)
    
    # 覆盖域名配置
    if args.domain:
        config['domain'] = args.domain
    
    # 验证必需配置
    if not config.get('domain') or config['domain'] == 'your-domain.com':
        print("请在配置文件中设置正确的域名")
        sys.exit(1)
    
    # 设置日志
    setup_logging(config.get('log_file', '/var/log/bgp_forwarder.log'),
                  config.get('log_level', 'INFO'))
    
    # 启动服务
    forwarder = BGPForwarder(config)
    forwarder.start()

if __name__ == "__main__":
    main()