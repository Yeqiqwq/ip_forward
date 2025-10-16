# 流量转发脚本

一个Python脚本，用于实现基于DNS解析的动态端口转发，支持全端口转发和完整的性能监控。

## 🚀 功能特性

### 核心功能
- **动态DNS解析**：每5秒自动查询目标域名的IP地址
- **全端口转发**：支持TCP/UDP协议的1-65535端口转发
- **智能故障恢复**：多DNS服务器故障转移，自动重试机制
- **实时性能监控**：详细的系统资源和网络统计
- **安全信号处理**：优雅的服务启停和资源清理

### 性能监控
- **系统资源监控**：CPU、内存、磁盘IO、网络IO
- **网络连接统计**：连接数、协议分布、连接状态分析
- **转发流量统计**：iptables规则统计、处理包数、转发流量
- **性能警告机制**：TIME_WAIT连接过多等异常检测

### 日志功能
- **分级日志输出**：支持DEBUG/INFO/WARNING/ERROR级别
- **双重日志记录**：同时输出到文件和控制台
- **性能指标记录**：定期输出系统和网络性能数据
- **详细操作日志**：DNS解析耗时、规则更新时间等

## 📋 系统要求

### 操作系统
- Linux发行版（推荐Ubuntu 18.04+、CentOS 7+）
- 需要root权限执行

### 硬件建议
- **CPU**：2核心以上（推荐4核心+）
- **内存**：2GB以上（推荐4GB+）
- **网络**：稳定的网络连接

## 🛠️ 安装部署

### 1. 下载脚本
```bash
# 下载脚本文件
wget https://your-domain.com/ip_forwarder.py
# 或
curl -O https://your-domain.com/ip_forwarder.py

# 添加执行权限
chmod +x ip_forwarder.py
```

### 2. 安装依赖
```bash
# Ubuntu/Debian
apt update
apt install python3 python3-pip iptables dnsutils -y
apt install python3-psutil

### 3. 创建配置文件
# 创建默认配置文件
python3 ip_forwarder.py --create-config

# 编辑配置文件
nano /etc/bgp_forwarder.json
```
## 🔧 使用方法

### 基本命令

#### 检查系统配置
```bash
python3 ip_forwarder.py --check-system
```
### 服务管理

#### 创建systemd服务（推荐）
```bash
# 创建服务文件
cat > /etc/systemd/system/bgp-forwarder.service << EOF
[Unit]
Description=BGP Port Forwarder Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/bgp-forwarder
ExecStart=/usr/bin/python3 /opt/bgp-forwarder/ip_forwarder.py -c /etc/bgp_forwarder.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 启用并启动服务
systemctl daemon-reload
systemctl enable bgp-forwarder
systemctl start bgp-forwarder

# 查看服务状态
systemctl status bgp-forwarder

# 查看服务日志
journalctl -u bgp-forwarder -f
```

## 📊 监控和日志

### 实时监控
```bash
# 查看实时日志
tail -f /var/log/bgp_forwarder.log

# 过滤性能监控日志
grep "性能监控" /var/log/bgp_forwarder.log

# 查看连接统计
grep "连接统计" /var/log/bgp_forwarder.log

# 查看转发统计
grep "转发统计" /var/log/bgp_forwarder.log
```

### 日志样例
```
2025-01-20 10:30:15 [INFO] BGP转发服务启动
2025-01-20 10:30:15 [INFO] BGP服务器IP: 192.168.1.100
2025-01-20 10:30:15 [INFO] 目标域名: example.com
2025-01-20 10:30:16 [INFO] DNS解析成功: example.com -> 203.0.113.10 (服务器: 223.5.5.5, 耗时: 45.2ms)
2025-01-20 10:30:16 [INFO] ✓ 全端口转发规则已设置到 203.0.113.10 (耗时: 125.8ms)
2025-01-20 10:30:45 [INFO] [性能监控] CPU: 15.2%(4核) | 内存: 1.8GB/8.0GB(22.5%) | 负载: 0.45,0.38,0.42
2025-01-20 10:30:45 [INFO] [连接统计] 总连接: 1250 | TCP: 1180 | UDP: 70 | 已建立: 1050 | 监听: 25
2025-01-20 10:30:45 [INFO] [转发统计] 处理包数: 485,239 | 转发流量: 2,847.3MB
```

## ⚙️ 配置参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `domain` | - | **必填**：目标域名 |
| `dns_server` | 223.5.5.5 | 主DNS服务器 |
| `backup_dns_servers` | [...] | 备用DNS服务器列表 |
| `check_interval` | 5 | DNS检查间隔（秒） |
| `timeout` | 10 | DNS查询超时时间（秒） |
| `retry_attempts` | 3 | DNS解析重试次数 |
| `log_file` | /var/log/bgp_forwarder.log | 日志文件路径 |
| `log_level` | INFO | 日志级别 |
| `log_interval` | 30 | 性能监控日志间隔（秒） |
| `iptables_chain_prefix` | BGP_FWD | iptables链前缀 |
| `max_errors` | 10 | 最大连续错误次数 |

## 🔍 故障排除

### 常见问题

#### 1. 权限错误
```bash
# 错误信息
需要root权限来修改iptables规则

# 解决方案
sudo python3 ip_forwarder.py
```

#### 2. DNS解析失败
```bash
# 检查DNS连通性
nslookup your-domain.com 223.5.5.5

# 检查网络连接
ping 223.5.5.5

# 尝试其他DNS服务器
nslookup your-domain.com 8.8.8.8
```

#### 3. iptables规则冲突
```bash
# 查看现有规则
iptables -t nat -L -n -v

# 手动清理冲突规则
iptables -t nat -F
iptables -F

# 重启服务
systemctl restart bgp-forwarder
```

#### 4. 高CPU使用率
```bash
# 检查连接数
ss -tuln | wc -l

# 调整检查间隔
# 在配置文件中增加 check_interval 值

# 监控系统资源
htop
```

### 性能优化建议

#### 系统级优化
```bash
# 增加连接跟踪表大小
echo 1048576 > /proc/sys/net/netfilter/nf_conntrack_max

# 优化网络缓冲区
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728

# 启用BBR拥塞控制
echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
sysctl -p
```

#### 应用级优化
```json
{
  "check_interval": 10,
  "log_interval": 60,
  "max_errors": 5
}
```

## ⚠️ 安全注意事项

### 重要警告
1. **SSH端口转发**：脚本会转发包括SSH 22端口在内的所有端口，请确保目标服务器安全
2. **防火墙配置**：建议在目标服务器配置适当的防火墙规则
3. **访问控制**：考虑限制源IP访问范围
4. **监控告警**：密切关注异常连接和流量

### 安全最佳实践
```bash
# 1. 更改SSH端口（目标服务器）
# /etc/ssh/sshd_config
Port 2222

# 2. 配置防火墙（目标服务器）
ufw enable
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp

# 3. 监控异常连接
netstat -tuln | grep :22

# 4. 定期检查日志
grep "WARNING\|ERROR" /var/log/bgp_forwarder.log
```

## 📈 性能基准

### 测试环境
- **CPU**：4核心 2.5GHz
- **内存**：8GB
- **网络**：1Gbps

### 性能指标
- **连接处理能力**：50,000+ 并发连接
- **转发延迟**：< 1ms
- **CPU使用率**：< 20%（正常负载）
- **内存使用**：< 500MB

## 🆘 技术支持

### 获取帮助
```bash
# 查看帮助信息
python3 ip_forwarder.py --help

# 系统配置检查
python3 ip_forwarder.py --check-system

# 详细调试模式
# 将配置文件中的 log_level 改为 "DEBUG"
```

### 问题报告
如果遇到问题，请提供以下信息：
1. 操作系统版本和架构
2. Python版本
3. 完整的错误日志
4. 网络环境描述
5. 配置文件内容（去除敏感信息）

---

**注意**：本脚本设计用于合法的网络转发需求，请确保遵守相关法律法规和服务条款。
