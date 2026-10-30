#!/bin/sh
# ==============================================================================
# OpenClash 流量监控面板 (Clash Traffic Monitor) - 卸载脚本
# ==============================================================================

set -e

APP_NAME="clash-traffic-monitor"
INSTALL_DIR="${INSTALL_DIR:-/opt/clash-traffic-monitor}"

echo "正在卸载 ${APP_NAME}..."

if command -v docker >/dev/null 2>&1; then
    if docker ps -a --format '{{.Names}}' | grep -Eq "^${APP_NAME}\$"; then
        docker stop "${APP_NAME}" >/dev/null 2>&1 || true
        docker rm "${APP_NAME}" >/dev/null 2>&1 || true
        echo "Docker 容器已移除。"
    fi
fi

if [ -f "/etc/init.d/${APP_NAME}" ]; then
    /etc/init.d/${APP_NAME} stop >/dev/null 2>&1 || true
    /etc/init.d/${APP_NAME} disable >/dev/null 2>&1 || true
    rm -f "/etc/init.d/${APP_NAME}"
    echo "系统守护服务已卸载。"
fi

echo "是否清理数据文件目录 (${INSTALL_DIR})? [y/N]"
# 默认保留数据文件保护历史统计
echo "已停止并移除运行实例。如需彻底删除数据，请手动执行: rm -rf ${INSTALL_DIR}"
