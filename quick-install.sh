#!/bin/sh
# ==============================================================================
# OpenClash 流量监控面板 (Clash Traffic Monitor) - iStoreOS / OpenWrt 一键安装脚本
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${GREEN}   ⚡ OpenClash 流量监控与多维分析面板 (iStoreOS) 安装器   ${NC}"
echo -e "${BLUE}======================================================${NC}"

APP_NAME="clash-traffic-monitor"
INSTALL_DIR="${INSTALL_DIR:-/opt/clash-traffic-monitor}"

echo -e "${YELLOW}» 目标安装路径: ${INSTALL_DIR}${NC}"
mkdir -p "${INSTALL_DIR}/data"
mkdir -p "${INSTALL_DIR}/templates"

# 复制文件
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo -e "${YELLOW}» 正在部署应用资产...${NC}"
cp -f "${SCRIPT_DIR}/index.html" "${INSTALL_DIR}/index.html"
cp -f "${SCRIPT_DIR}/index.html" "${INSTALL_DIR}/templates/index.html"
cp -f "${SCRIPT_DIR}/server.py" "${INSTALL_DIR}/server.py"
cp -f "${SCRIPT_DIR}/GeoLite2-Country.mmdb" "${INSTALL_DIR}/GeoLite2-Country.mmdb" 2>/dev/null || true
cp -f "${SCRIPT_DIR}/docker-compose.yml" "${INSTALL_DIR}/docker-compose.yml" 2>/dev/null || true
cp -f "${SCRIPT_DIR}/Dockerfile" "${INSTALL_DIR}/Dockerfile" 2>/dev/null || true

# 检查是否具备 Docker
if command -v docker >/dev/null 2>&1; then
    echo -e "${GREEN}» 检测到 Docker 环境，使用 Docker 容器化部署模式...${NC}"
    
    # 停止已有容器
    if docker ps -a --format '{{.Names}}' | grep -Eq "^${APP_NAME}\$"; then
        echo -e "${YELLOW}» 停止并移除已有 ${APP_NAME} 容器...${NC}"
        docker stop "${APP_NAME}" >/dev/null 2>&1 || true
        docker rm "${APP_NAME}" >/dev/null 2>&1 || true
    fi

    # 优先使用本地镜像，若无则拉取 GHCR 镜像
    IMAGE_NAME="ghcr.io/lawzhougc/clash-traffic-monitor:latest"
    if docker images --format '{{.Repository}}:{{.Tag}}' | grep -Eq "^${APP_NAME}:latest\$"; then
        IMAGE_NAME="${APP_NAME}:latest"
        echo -e "${GREEN}» 使用本地已存在的 Docker 镜像: ${IMAGE_NAME}${NC}"
    else
        echo -e "${YELLOW}» 正在拉取 Docker 镜像: ${IMAGE_NAME}...${NC}"
        docker pull "${IMAGE_NAME}" || IMAGE_NAME="${APP_NAME}:latest"
    fi

    echo -e "${YELLOW}» 正在启动 Docker 容器...${NC}"
    docker run -d \
        --name "${APP_NAME}" \
        --restart unless-stopped \
        --network host \
        -v "${INSTALL_DIR}/server.py:/app/server.py" \
        -v "${INSTALL_DIR}/index.html:/app/templates/index.html" \
        -v "${INSTALL_DIR}/data:/app/data" \
        -v "${INSTALL_DIR}/GeoLite2-Country.mmdb:/app/GeoLite2-Country.mmdb" \
        "${IMAGE_NAME}"

    echo -e "${GREEN}✔ Docker 容器 ${APP_NAME} 已成功运行！${NC}"
else
    echo -e "${YELLOW}» 未检测到 Docker，尝试以 Python 原生系统服务模式部署...${NC}"
    
    if command -v opkg >/dev/null 2>&1; then
        echo -e "${YELLOW}» 检查 Python 运行依赖...${NC}"
        opkg update >/dev/null 2>&1 || true
        opkg install python3 python3-pip >/dev/null 2>&1 || true
    fi

    pip install --no-cache-dir fastapi uvicorn websockets || pip3 install --no-cache-dir fastapi uvicorn websockets

    # 注册 procd 服务
    INIT_SCRIPT="/etc/init.d/${APP_NAME}"
    cat << 'EOF' > "${INIT_SCRIPT}"
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

PROG="/usr/bin/python3"
DIR="/opt/clash-traffic-monitor"

start_service() {
    procd_open_instance
    procd_set_param command "$PROG" "$DIR/server.py"
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
EOF
    chmod +x "${INIT_SCRIPT}"
    "${INIT_SCRIPT}" enable
    "${INIT_SCRIPT}" restart
    echo -e "${GREEN}✔ 原生系统守护服务已注册并启动！${NC}"
fi

# 获取当前局域网 IP
LAN_IP="127.0.0.1"
if command -v uci >/dev/null 2>&1; then
    LAN_IP=$(uci get network.lan.ipaddr 2>/dev/null || echo "127.0.0.1")
fi

echo -e "\n${BLUE}======================================================${NC}"
echo -e "${GREEN}🎉 安装部署全部完成！${NC}"
echo -e "大屏访问地址: ${YELLOW}http://${LAN_IP}:8099${NC}"
echo -e "配置文件路径: ${YELLOW}${INSTALL_DIR}${NC}"
echo -e "${BLUE}======================================================${NC}\n"
