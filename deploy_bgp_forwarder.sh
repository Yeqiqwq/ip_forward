#!/bin/bash
#
# BGP Forwarder 一键部署脚本
# 功能：自动安装依赖、配置域名、创建systemd服务并启动
#

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置变量
SCRIPT_NAME="ip_forwarder.py"
SERVICE_NAME="bgp-forwarder"
INSTALL_DIR="/opt/bgp-forwarder"
CONFIG_FILE="/etc/bgp_forwarder.json"
LOG_DIR="/var/log"
PYTHON_SCRIPT=""

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否以 root 运行
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "请使用 root 权限运行此脚本"
        print_info "使用方法: sudo bash $0"
        exit 1
    fi
    print_success "权限检查通过"
}

# 检测系统类型
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        OS_TYPE=$ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        OS_TYPE=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    elif [[ -f /etc/lsb-release ]]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        OS_TYPE=$(echo $DISTRIB_ID | tr '[:upper:]' '[:lower:]')
    elif [[ -f /etc/debian_version ]]; then
        OS="Debian"
        OS_TYPE="debian"
    elif [[ -f /etc/redhat-release ]]; then
        OS="Red Hat"
        OS_TYPE="rhel"
    else
        OS=$(uname -s)
        OS_TYPE="unknown"
    fi
    print_info "检测到系统: $OS"
}

# 安装依赖
install_dependencies() {
    print_info "正在安装依赖..."
    
    case $OS_TYPE in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq python3 python3-pip dnsutils iptables curl
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &> /dev/null; then
                dnf install -y python3 python3-pip bind-utils iptables curl
            else
                yum install -y python3 python3-pip bind-utils iptables curl
            fi
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm python python-pip bind iptables curl
            ;;
        alpine)
            apk add --no-cache python3 py3-pip bind-tools iptables curl
            ;;
        *)
            print_warning "未知的系统类型，尝试通用安装方式..."
            if command -v apt-get &> /dev/null; then
                apt-get update -qq
                apt-get install -y -qq python3 python3-pip dnsutils iptables curl
            elif command -v yum &> /dev/null; then
                yum install -y python3 python3-pip bind-utils iptables curl
            elif command -v dnf &> /dev/null; then
                dnf install -y python3 python3-pip bind-utils iptables curl
            else
                print_error "无法自动安装依赖，请手动安装: python3, pip, nslookup/dig, iptables, curl"
                exit 1
            fi
            ;;
    esac
    
    print_success "系统依赖安装完成"
    
    # 安装 Python 依赖
    print_info "正在安装 Python 依赖..."
    pip3 install --quiet psutil 2>/dev/null || pip install --quiet psutil 2>/dev/null
    print_success "Python 依赖安装完成"
}

# 查找或下载 Python 脚本
find_python_script() {
    print_info "查找 Python 脚本..."
    
    # 优先查找当前目录
    if [[ -f "./ip_forwarder.py" ]]; then
        PYTHON_SCRIPT="./ip_forwarder.py"
        print_success "找到脚本: $PYTHON_SCRIPT"
        return
    fi
    
    # 查找常见下载目录
    for dir in "/root/.openclaw/qqbot/downloads" "/tmp" "$HOME/Downloads" "."; do
        if [[ -f "$dir/ip_forwarder.py" ]]; then
            PYTHON_SCRIPT="$dir/ip_forwarder.py"
            print_success "找到脚本: $PYTHON_SCRIPT"
            return
        fi
    done
    
    # 如果找不到，尝试从当前目录查找任何 .py 文件
    PYTHON_FILE=$(find . -maxdepth 1 -name "*.py" -type f 2>/dev/null | head -1)
    if [[ -n "$PYTHON_FILE" ]]; then
        PYTHON_SCRIPT="$PYTHON_FILE"
        print_warning "未找到 ip_forwarder.py，使用找到的脚本: $PYTHON_SCRIPT"
        return
    fi
    
    print_error "未找到 Python 转发脚本"
    print_info "请确保 ip_forwarder.py 在当前目录，或指定脚本路径"
    exit 1
}

# 获取用户输入域名
get_domain_input() {
    echo ""
    echo "========================================"
    echo "   BGP Forwarder 配置"
    echo "========================================"
    echo ""
    
    while true; do
        read -p "请输入目标转发域名 (例如: target.example.com): " DOMAIN
        
        # 验证域名格式
        if [[ -z "$DOMAIN" ]]; then
            print_error "域名不能为空"
            continue
        fi
        
        # 简单验证域名格式
        if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            print_warning "域名格式可能不正确，请确认"
            read -p "是否继续使用此域名? (y/n): " confirm
            if [[ $confirm != [yY] ]]; then
                continue
            fi
        fi
        
        # 测试 DNS 解析
        print_info "测试域名 $DOMAIN 的 DNS 解析..."
        if nslookup "$DOMAIN" &>/dev/null || dig +short "$DOMAIN" &>/dev/null; then
            print_success "域名解析成功"
        else
            print_warning "域名解析失败，请确保域名配置正确"
            read -p "是否继续使用此域名? (y/n): " confirm
            if [[ $confirm != [yY] ]]; then
                continue
            fi
        fi
        
        break
    done
    
    echo ""
    print_success "域名配置: $DOMAIN"
}

# 获取可选配置
get_optional_config() {
    echo ""
    print_info "可选配置 (直接回车使用默认值)"
    echo ""
    
    # DNS 服务器
    read -p "主 DNS 服务器 [223.5.5.5]: " DNS_SERVER
    DNS_SERVER=${DNS_SERVER:-223.5.5.5}
    
    # 检查间隔
    read -p "DNS 检查间隔(秒) [5]: " CHECK_INTERVAL
    CHECK_INTERVAL=${CHECK_INTERVAL:-5}
    
    # 日志级别
    echo "日志级别选项: DEBUG, INFO, WARNING, ERROR"
    read -p "日志级别 [INFO]: " LOG_LEVEL
    LOG_LEVEL=${LOG_LEVEL:-INFO}
    
    print_success "配置完成"
}

# 创建安装目录和复制文件
setup_files() {
    print_info "创建安装目录..."
    
    # 创建目录
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$LOG_DIR"
    
    # 复制 Python 脚本
    cp "$PYTHON_SCRIPT" "$INSTALL_DIR/$SCRIPT_NAME"
    chmod +x "$INSTALL_DIR/$SCRIPT_NAME"
    
    print_success "文件已复制到 $INSTALL_DIR"
}

# 创建配置文件
create_config() {
    print_info "创建配置文件..."
    
    cat > "$CONFIG_FILE" << EOF
{
  "domain": "$DOMAIN",
  "dns_server": "$DNS_SERVER",
  "backup_dns_servers": ["114.114.114.114", "8.8.8.8", "1.1.1.1"],
  "check_interval": $CHECK_INTERVAL,
  "timeout": 10,
  "retry_attempts": 3,
  "log_file": "$LOG_DIR/bgp_forwarder.log",
  "log_level": "$LOG_LEVEL",
  "log_interval": 30,
  "iptables_chain_prefix": "BGP_FWD",
  "max_errors": 10
}
EOF
    
    chmod 644 "$CONFIG_FILE"
    print_success "配置文件已创建: $CONFIG_FILE"
}

# 创建 systemd 服务
create_systemd_service() {
    print_info "创建 systemd 服务..."
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << 'EOF'
[Unit]
Description=BGP Forwarder Service
Documentation=https://github.com/your-repo/ip_forward
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/bgp-forwarder
ExecStart=/usr/bin/python3 /opt/bgp-forwarder/ip_forwarder.py -c /etc/bgp_forwarder.json
ExecStop=/bin/kill -TERM $MAINPID
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StartLimitInterval=60s
StartLimitBurst=3

# 安全设置
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false

# 日志输出
StandardOutput=journal
StandardError=journal
SyslogIdentifier=bgp-forwarder

[Install]
WantedBy=multi-user.target
EOF
    
    # 重新加载 systemd
    systemctl daemon-reload
    
    # 启用开机自启
    systemctl enable "$SERVICE_NAME"
    
    print_success "systemd 服务已创建并启用开机自启"
}

# 启动服务
start_service() {
    print_info "启动 BGP Forwarder 服务..."
    
    # 启动服务
    if systemctl start "$SERVICE_NAME"; then
        print_success "服务启动成功"
    else
        print_error "服务启动失败"
        print_info "查看日志: journalctl -u $SERVICE_NAME -n 50"
        return 1
    fi
    
    # 等待一下检查状态
    sleep 2
    
    # 检查服务状态
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "服务运行正常"
    else
        print_warning "服务状态异常，请检查日志"
    fi
}

# 显示部署信息
show_summary() {
    echo ""
    echo "========================================"
    echo "   部署完成！"
    echo "========================================"
    echo ""
    echo -e "  安装目录: ${GREEN}$INSTALL_DIR${NC}"
    echo -e "  配置文件: ${GREEN}$CONFIG_FILE${NC}"
    echo -e "  日志文件: ${GREEN}$LOG_DIR/bgp_forwarder.log${NC}"
    echo -e "  服务名称: ${GREEN}$SERVICE_NAME${NC}"
    echo ""
    echo -e "  目标域名: ${GREEN}$DOMAIN${NC}"
    echo -e "  DNS 服务器: ${GREEN}$DNS_SERVER${NC}"
    echo -e "  检查间隔: ${GREEN}${CHECK_INTERVAL}秒${NC}"
    echo ""
    echo "========================================"
    echo "   常用命令"
    echo "========================================"
    echo ""
    echo "  查看状态:  systemctl status $SERVICE_NAME"
    echo "  启动服务:  systemctl start $SERVICE_NAME"
    echo "  停止服务:  systemctl stop $SERVICE_NAME"
    echo "  重启服务:  systemctl restart $SERVICE_NAME"
    echo "  查看日志:  journalctl -u $SERVICE_NAME -f"
    echo "  查看日志:  tail -f $LOG_DIR/bgp_forwarder.log"
    echo ""
    echo "========================================"
}

# 卸载函数
uninstall() {
    print_warning "正在卸载 BGP Forwarder..."
    
    # 停止并禁用服务
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    
    # 删除服务文件
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    
    # 删除安装文件
    rm -rf "$INSTALL_DIR"
    rm -f "$CONFIG_FILE"
    
    print_success "卸载完成"
    exit 0
}

# 主函数
main() {
    # 检查是否为卸载模式
    if [[ "$1" == "--uninstall" || "$1" == "-u" ]]; then
        check_root
        uninstall
    fi
    
    # 显示欢迎信息
    echo ""
    echo "========================================"
    echo "   BGP Forwarder 一键部署脚本"
    echo "========================================"
    echo ""
    
    # 执行部署步骤
    check_root
    detect_os
    install_dependencies
    find_python_script
    get_domain_input
    get_optional_config
    setup_files
    create_config
    create_systemd_service
    start_service
    show_summary
}

# 处理脚本参数
case "${1:-}" in
    --help|-h)
        echo "BGP Forwarder 部署脚本"
        echo ""
        echo "用法: sudo bash $0 [选项]"
        echo ""
        echo "选项:"
        echo "  -h, --help       显示帮助信息"
        echo "  -u, --uninstall  卸载服务"
        echo ""
        echo "示例:"
        echo "  sudo bash $0              # 部署服务"
        echo "  sudo bash $0 --uninstall  # 卸载服务"
        exit 0
        ;;
    --uninstall|-u)
        main "$1"
        ;;
    "")
        main
        ;;
    *)
        print_error "未知参数: $1"
        echo "使用 --help 查看帮助"
        exit 1
        ;;
esac
