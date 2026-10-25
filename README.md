# ⚡ OpenClash 流量监控与多维分析面板 (Clash Traffic Monitor)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-brightgreen.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-v3-38B2AC.svg)](https://tailwindcss.com/)
[![Vue 3](https://img.shields.io/badge/Vue-3.x-4FC08D.svg)](https://vuejs.org/)

专为 **iStoreOS / OpenWrt / Linux 旁路由** 与网关环境量身打造的高性能、极致轻量级 OpenClash / Mihomo 流量统计与实时分析面板。

单文件轻量设计，内置离线 GeoIP 国旗解析、一键深色模式、设备别名、免重启热切换目标旁路由、数据保留周期管理与访问密码保护，内存开销仅 **30MB ~ 50MB**，软路由闪存与 CPU 零压力。

---

## 🌟 核心特性

- 🚀 **极致轻量无负担**：
  无需编译庞大的 Node.js 运行时或重型列式数据库。纯 Python 3 原生实现，后端仅依赖 `FastAPI` + `uvicorn` + `websockets`，前端为零构建的单文件 SPA，整体内存占用仅 **30MB~50MB**。
- 🗺️ **内置纯 Python 离线 GeoIP 解析**：
  无需安装任何 C 语言扩展，内置纯 Python 高性能 MMDB 解析引擎与 `GeoLite2-Country` 离线库。自动在域名列表、节点列表与并发连接中精准渲染国家/地区国旗（如 🇺🇸、🇯🇵、🇭🇰、🇸🇬、🇩🇪、🇬🇧、🇹🇼 等）。
- 🌙 **一键深色模式 (Dark Mode)**：
  提供顶部一键切换昼夜主题，Tailwind 深度适配，ECharts 图表自适应坐标轴与网格配色，保护夜间视力。
- 🎯 **深度适配 OpenClash / Mihomo 分流架构**：
  专为出国订阅场景打磨，智能递归解析多层 `chains` 嵌套，精准提取底层实际落地的**叶子节点**（如 `Fast-B2-1`），智能剔除 DIRECT 直连流量，还原最纯净的出国节点流量消耗。
- 🏷️ **内网设备自定义别名**：
  点击任意局域网 IP（如 `192.168.1.10`）即可快速设置设备别名（如「客厅 Apple TV」「办公电脑」），全站概览饼图、趋势折线、排行柱状图与实时连接表全局联动。
- 🌐 **前端免重启热切换旁路由**：
  在「设置」页面中可直接配置目标旁路由 IP、REST API 端口（默认 9090）与 Secret 密钥，点击「测试并保存」后系统自动发起 HTTP 探测握手并毫秒级重连 WebSocket，无需重启 Docker 容器。
- 🗄️ **存储容量与生命周期管理**：
  可视化展示本地 SQLite 数据库体积、历史记录条数与时间跨度。支持配置 30天 / 60天 / 90天 / 180天 定时自动清理过期记录，每 12 小时自动巡检并执行 `VACUUM` 整理磁盘碎片，提供一键手动清理旧数据按钮。
- 🔐 **内置访问控制与安全密码**：
  自带 Token 鉴权中间件与管理密码保护，无需配置复杂反代即可防范内网随意查看。

---

## 📸 功能页面速览

| 模块 | 说明 |
| :--- | :--- |
| **概览** | 实时带宽动态折线图（下行/上行速率）、设备流量占比环形图、出国出口节点流量排行 |
| **流量** | 当前统计周期内的流量消耗总报（总消耗、分设备、出口节点、目标网站） |
| **设备** | 局域网真实客户端源 IP 与流量构成，支持一键修改设备别名 |
| **节点** | 出国代理节点承载分析，自动解析国家/地区国旗图标 |
| **域名** | 按目标网站/域名维度分析流量走向，带国家归属地国旗 |
| **连接** | 展示当前走节点通道的高速并发会话列表，毫秒级刷新 |
| **明细** | 设备 × 分流规则 × 落地节点 三维组合明细日志 |
| **设置** | 本地数据存储与自动清理策略、旁路由目标客户端配置、访问控制安全设置 |

---

## 🚀 快速开始

### 方式一：Docker Run 快速启动 (推荐)

在旁路由（如 iStoreOS / OpenWrt）终端执行：

```bash
docker run -d \
  --name clash-traffic-monitor \
  --restart unless-stopped \
  --network host \
  -v /path/to/your/data:/app/data \
  clash-traffic-monitor:latest
```

> **提示**：如果宿主机的 8099 端口未冲突，使用 `--network host` 可直接访问本机 127.0.0.1:9090 的 OpenClash 控制器，并打开 `http://<路由器IP>:8099` 访问监控大屏。

---

### 方式二：Docker Compose 启动

创建 `docker-compose.yml`：

```yaml
version: '3.8'

services:
  clash-traffic-monitor:
    image: clash-traffic-monitor:latest
    build: .
    container_name: clash-traffic-monitor
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./data:/app/data
    environment:
      - TZ=Asia/Shanghai
```

启动服务：

```bash
docker compose up -d
```

---

### 方式三：源码直接运行 (Python 3.11+)

```bash
# 1. 克隆仓库
git clone https://github.com/lawzhougc/clash-traffic-monitor.git
cd clash-traffic-monitor

# 2. 安装依赖
pip install fastapi uvicorn websockets

# 3. 运行服务 (默认监听 8099 端口)
python server.py
```

打开浏览器访问：`http://localhost:8099`

---

## ⚙️ 初始配置指南

1. **首次打开面板**：打开 `http://<路由器IP>:8099`。
2. **连接 OpenClash**：点击左侧菜单栏底部的 **「设置」**：
   - **旁路由 IP**：同机部署填 `127.0.0.1`，如果面板部署在其它 NAS/PC 上，填入旁路由内网 IP（如 `192.168.x.x`）；
   - **API 端口**：OpenClash 外部控制默认端口 `9090`；
   - **API 密钥**：OpenClash 全局设置中的 Controller Secret；
   - 点击 **「测试并保存连接」**，提示成功后系统立即开始实时抓取。
3. **开启访问密码**（可选）：在「安全与访问控制」模块中勾选「启用管理访问密码」，输入新密码即可生效。

---

## 🛠️ 技术栈

- **后端**：Python 3.11+, FastAPI, Uvicorn, WebSockets, SQLite3 (WAL 模式)
- **前端**：Vue 3 (Composition API), Tailwind CSS (支持 Dark Mode), Apache ECharts 5
- **GeoIP**：Pure-Python MaxMind DB Reader, GeoLite2-Country 离线库

---

## 📄 开源许可证

本项目基于 [MIT 许可证](LICENSE) 开源发布。
