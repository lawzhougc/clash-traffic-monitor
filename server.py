import re
import asyncio
import json
import sqlite3
import datetime
import os
import hashlib
import time
from typing import Optional
from collections import deque
from contextlib import asynccontextmanager
import websockets
import urllib.request
import urllib.error
from fastapi import FastAPI, Query, Body, Response, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn

DB_PATH = "/app/data/traffic.db"
WEB_PORT = 8099

SVG_FAVICON = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>
<defs>
<linearGradient id='g' x1='0%' y1='0%' x2='100%' y2='100%'>
<stop offset='0%' stop-color='#2563eb'/>
<stop offset='100%' stop-color='#6366f1'/>
</linearGradient>
</defs>
<rect width='32' height='32' rx='8' fill='url(#g)'/>
<path d='M18 4L7 17h7l-2 11 11-13h-7l2-11z' fill='#ffffff'/>
</svg>"""

os.makedirs("/app/data", exist_ok=True)

# ================= 轻量纯 Python 离线 GeoIP MMDB 解析引擎 =================
import socket
import struct

class GeoLiteReader:
    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, 'rb') as f:
            self.buf = f.read()
        marker = b'\xab\xcd\xefMaxMind.com'
        pos = self.buf.rfind(marker)
        if pos == -1:
            raise ValueError('Invalid MMDB database format')
        meta, _ = self._decode(pos + len(marker), 0)
        self.node_count = meta.get('node_count', 0)
        self.record_size = meta.get('record_size', 24)
        self.tree_size = self.node_count * (self.record_size * 2 // 8)
        self.data_section_start = self.tree_size + 16

    def lookup(self, ip_str):
        try:
            packed = socket.inet_aton(ip_str)
            ip_bits = b'\x00' * 12 + packed
        except:
            return None

        node = 0
        for byte in ip_bits:
            for bit in range(7, -1, -1):
                direction = (byte >> bit) & 1
                offset = node * 6 + (3 if direction else 0)
                node = (self.buf[offset] << 16) | (self.buf[offset+1] << 8) | self.buf[offset+2]
                if node >= self.node_count:
                    break
            if node >= self.node_count:
                break

        if node == self.node_count:
            return None
        
        data_offset = self.data_section_start + (node - self.node_count - 16)
        res, _ = self._decode(data_offset, 0)
        return res

    def _decode(self, offset, depth=0):
        if depth > 30 or offset >= len(self.buf):
            return None, offset
        ctrl = self.buf[offset]
        offset += 1
        dtype = ctrl >> 5
        size = ctrl & 0x1f
        if dtype == 0:
            dtype = 7 + self.buf[offset]
            offset += 1
        if size == 29:
            size = 29 + self.buf[offset]
            offset += 1
        elif size == 30:
            size = 285 + struct.unpack('>H', self.buf[offset:offset+2])[0]
            offset += 2
        elif size == 31:
            size = 65821 + (self.buf[offset]<<16 | self.buf[offset+1]<<8 | self.buf[offset+2])
            offset += 3

        if dtype == 1:
            ss = (ctrl >> 3) & 0x3
            if ss == 0:
                ptr = self.data_section_start + ((ctrl & 0x7) << 8 | self.buf[offset])
                offset += 1
            elif ss == 1:
                ptr = self.data_section_start + 2048 + ((ctrl & 0x7) << 16 | self.buf[offset] << 8 | self.buf[offset+1])
                offset += 2
            elif ss == 2:
                ptr = self.data_section_start + 526336 + ((ctrl & 0x7) << 24 | self.buf[offset] << 16 | self.buf[offset+1] << 8 | self.buf[offset+2])
                offset += 3
            else:
                ptr = self.data_section_start + int.from_bytes(self.buf[offset:offset+4], 'big')
                offset += 4
            val, _ = self._decode(ptr, depth + 1)
            return val, offset
        elif dtype == 2:
            val = self.buf[offset:offset+size].decode('utf-8', errors='ignore')
            return val, offset + size
        elif dtype in (5, 6):
            val = int.from_bytes(self.buf[offset:offset+size], 'big') if size else 0
            return val, offset + size
        elif dtype == 7:
            m = {}
            for _ in range(size):
                k, offset = self._decode(offset, depth + 1)
                v, offset = self._decode(offset, depth + 1)
                m[k] = v
            return m, offset
        elif dtype == 11:
            arr = []
            for _ in range(size):
                v, offset = self._decode(offset, depth + 1)
                arr.append(v)
            return arr, offset
        elif dtype == 14:
            return size != 0, offset
        else:
            return None, offset + size

# 全局初始化 GeoIP 库
geo_reader = None
for mmdb_path in [
    '/app/GeoLite2-Country.mmdb',
    '/app/data/GeoLite2-Country.mmdb',
    './GeoLite2-Country.mmdb',
    '/etc/openclash/Country.mmdb',
    'Country.mmdb'
]:
    if os.path.exists(mmdb_path):
        try:
            geo_reader = GeoLiteReader(mmdb_path)
            print(f"[GeoIP] 成功加载离线 GeoIP 数据库: {mmdb_path}")
            break
        except Exception as e:
            print(f"[GeoIP] 加载 {mmdb_path} 异常: {e}")

# 内存域名/IP Geo 缓存字典
domain_flag_cache = {}

def iso_to_flag(code):
    if not code or len(code) != 2:
        return '🌐'
    try:
        return chr(ord(code[0].upper()) - 65 + 0x1F1E6) + chr(ord(code[1].upper()) - 65 + 0x1F1E6)
    except:
        return '🌐'

def extract_node_flag(node_name):
    if not node_name:
        return '🌐'
    # 1. 优先提取节点名称内已存在的 Emoji 国旗字符
    flag_match = re.search(r'[🇦-🇿]{2}|🏴‍☠️|🏁|🚩', node_name)
    if flag_match:
        return flag_match.group(0)

    # 2. 启发式关键词规则匹配
    patterns = [
        (r'(?i)(\bHK\b|Hong\s*Kong|香港)', '🇭🇰'),
        (r'(?i)(\bJP\b|Japan|日本|Tokyo|东京|Osaka|大阪)', '🇯🇵'),
        (r'(?i)(\bUS\b|United\s*States|USA|美国|\b美\b|Los\s*Angeles|Silicon|洛杉矶|硅谷)', '🇺🇸'),
        (r'(?i)(\bSG\b|Singapore|新加坡|狮城)', '🇸🇬'),
        (r'(?i)(\bTW\b|Taiwan|台湾|台北)', '🇹🇼'),
        (r'(?i)(\bKR\b|Korea|韩国|首尔)', '🇰🇷'),
        (r'(?i)(\bUK\b|\bGB\b|Britain|英国|伦敦|London)', '🇬🇧'),
        (r'(?i)(\bDE\b|Germany|德国|Frankfurt|法兰克福)', '🇩🇪'),
        (r'(?i)(\bFR\b|France|法国|巴黎|Paris)', '🇫🇷'),
        (r'(?i)(\bAU\b|Australia|澳大利亚|悉尼|Sydney)', '🇦🇺'),
        (r'(?i)(\bCA\b|Canada|加拿大)', '🇨🇦'),
        (r'(?i)(\bRU\b|Russia|俄罗斯)', '🇷🇺'),
        (r'(?i)(\bNL\b|Netherlands|荷兰)', '🇳🇱'),
        (r'(?i)(\bCN\b|China|中国|国内)', '🇨🇳'),
        (r'(?i)(DIRECT|直连)', '⚡')
    ]
    for pattern, flag in patterns:
        if re.search(pattern, node_name):
            return flag
    return '🌐'

def resolve_domain_flag(host, dest_ip=None):
    if not host:
        return '🌐'
    host_lower = host.lower()
    if host_lower in domain_flag_cache:
        return domain_flag_cache[host_lower]

    # 1. 如果有目标 IP 且加载了 GeoIP，先查 IP
    if dest_ip and geo_reader:
        try:
            res = geo_reader.lookup(dest_ip)
            if res:
                c = res.get('country') or res.get('registered_country') or {}
                iso = c.get('iso_code')
                if iso:
                    flag = iso_to_flag(iso)
                    domain_flag_cache[host_lower] = flag
                    return flag
        except:
            pass

    # 2. 顶级域名后缀判断
    tlds = [
        ('.cn', '🇨🇳'), ('.jp', '🇯🇵'), ('.hk', '🇭🇰'), ('.tw', '🇹🇼'),
        ('.uk', '🇬🇧'), ('.de', '🇩🇪'), ('.sg', '🇸🇬'), ('.kr', '🇰🇷'),
        ('.ru', '🇷🇺'), ('.fr', '🇫🇷'), ('.au', '🇦🇺'), ('.ca', '🇨🇦')
    ]
    for suffix, flag in tlds:
        if host_lower.endswith(suffix):
            domain_flag_cache[host_lower] = flag
            return flag

    # 3. 常见跨国服务服务商判断
    us_services = ['google', 'youtube', 'facebook', 'instagram', 'twitter', 'github', 'openai', 'anthropic', 'netflix', 'amazon', 'apple', 'microsoft', 'cloudflare']
    for s in us_services:
        if s in host_lower:
            domain_flag_cache[host_lower] = '🇺🇸'
            return '🇺🇸'

    cn_services = ['baidu', 'bilibili', 'qq.com', 'taobao', 'jd.com', 'weibo', 'alipay', 'aliyun', 'tencent']
    for s in cn_services:
        if s in host_lower:
            domain_flag_cache[host_lower] = '🇨🇳'
            return '🇨🇳'

    domain_flag_cache[host_lower] = '🌐'
    return '🌐'


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS traffic_daily (
        date TEXT,
        device_ip TEXT,
        rule TEXT,
        node_name TEXT,
        group_name TEXT,
        upload_bytes INTEGER DEFAULT 0,
        download_bytes INTEGER DEFAULT 0,
        PRIMARY KEY (date, device_ip, rule, node_name, group_name)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS traffic_domain_daily (
        date TEXT,
        host TEXT,
        upload_bytes INTEGER DEFAULT 0,
        download_bytes INTEGER DEFAULT 0,
        PRIMARY KEY (date, host)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS domain_geo (
        host TEXT PRIMARY KEY,
        country_code TEXT,
        flag TEXT,
        updated_at TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS device_alias (
        ip TEXT PRIMARY KEY,
        name TEXT,
        updated_at TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)
    # 默认设置项
    defaults = {
        "clash_host": "127.0.0.1",
        "clash_port": "9090",
        "clash_secret": "",
        "retention_days": "90",
        "auth_enabled": "0",
        "auth_password": ""
    }
    for k, v in defaults.items():
        c.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)", (k, v))

    c.execute("INSERT OR IGNORE INTO device_alias (ip, name, updated_at) VALUES ('192.168.1.10', '当前管理终端 (192.168.1.10)', datetime('now'))")
    c.execute("INSERT OR IGNORE INTO device_alias (ip, name, updated_at) VALUES ('127.0.0.1', '旁路由本机', datetime('now'))")
    conn.commit()
    conn.close()

init_db()

def get_setting(key: str, default: str = "") -> str:
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
    row = c.fetchone()
    conn.close()
    return row["value"] if row else default

def set_setting(key: str, value: str):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO system_settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
    """, (key, str(value)))
    conn.commit()
    conn.close()

# 活跃 Token 会话集合
active_tokens = set()

def create_token(password: str) -> str:
    salt = "clash_traffic_monitor_salt"
    token = hashlib.sha256(f"{password}_{salt}_{time.time()}".encode()).hexdigest()
    active_tokens.add(token)
    return token

security = HTTPBearer(auto_error=False)

def check_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    auth_enabled = get_setting("auth_enabled", "0") == "1"
    if not auth_enabled:
        return True
    if not credentials:
        raise HTTPException(status_code=401, detail="请先登录访问控制")
    token = credentials.credentials
    if token not in active_tokens:
        raise HTTPException(status_code=401, detail="凭证已过期或无效，请重新登录")
    return True

# 内存状态与任务
active_conns = {}
current_live_conns = []
current_speed = {"up": 0, "down": 0}
traffic_history = deque(maxlen=60)
collector_restart_event = asyncio.Event()

async def clash_traffic_task():
    """实时监听 OpenClash /traffic 速率并保留最近 60 秒历史"""
    while True:
        host = get_setting("clash_host", "127.0.0.1")
        port = get_setting("clash_port", "9090")
        secret = get_setting("clash_secret", "")
        ws_url = f"ws://{host}:{port}/traffic"
        if secret:
            ws_url += f"?token={secret}"
        try:
            async with websockets.connect(ws_url, ping_interval=None) as ws:
                while not collector_restart_event.is_set():
                    msg = await asyncio.wait_for(ws.recv(), timeout=5)
                    data = json.loads(msg)
                    up_s = data.get("up", 0)
                    down_s = data.get("down", 0)
                    current_speed["up"] = up_s
                    current_speed["down"] = down_s
                    now_str = datetime.datetime.now().strftime("%H:%M:%S")
                    traffic_history.append({
                        "time": now_str,
                        "up": up_s,
                        "down": down_s
                    })
        except Exception:
            await asyncio.sleep(2)

async def clash_collector_task():
    """实时监听 OpenClash /connections 流量增量并写入数据库"""
    while True:
        host = get_setting("clash_host", "127.0.0.1")
        port = get_setting("clash_port", "9090")
        secret = get_setting("clash_secret", "")
        ws_url = f"ws://{host}:{port}/connections"
        if secret:
            ws_url += f"?token={secret}"

        buffer = {}
        domain_buffer = {}
        last_flush = datetime.datetime.now()
        collector_restart_event.clear()

        try:
            print(f"[Collector] 正在连接 OpenClash: {ws_url} ...")
            async with websockets.connect(ws_url, ping_interval=None, max_size=30*1024*1024) as ws:
                print("[Collector] 成功连接 OpenClash WebSocket，开始实时流量采集")
                while not collector_restart_event.is_set():
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=8)
                    except asyncio.TimeoutError:
                        continue

                    data = json.loads(msg)
                    conns = data.get("connections", [])
                    current_ids = set()
                    today = datetime.date.today().isoformat()

                    live_snapshot = []
                    for c in conns:
                        cid = c.get("id")
                        current_ids.add(cid)
                        chains = c.get("chains", [])
                        if not chains:
                            continue

                        node_name = chains[0]
                        if node_name.upper() in ["DIRECT", "REJECT", "GLOBAL"]:
                            continue

                        group_name = chains[-1] if len(chains) > 1 else "默认"
                        metadata = c.get("metadata", {})
                        source_ip = metadata.get("sourceIP") or "127.0.0.1"
                        host_name = metadata.get("host") or metadata.get("destinationIP") or ""
                        rule = c.get("rule", "Unknown")
                        rule_payload = c.get("rulePayload", "")
                        rule_display = f"{rule}({rule_payload})" if rule_payload else rule

                        upload = c.get("upload", 0)
                        download = c.get("download", 0)

                        if cid in active_conns:
                            last_up, last_down = active_conns[cid]
                            delta_up = max(0, upload - last_up)
                            delta_down = max(0, download - last_down)
                        else:
                            delta_up = upload
                            delta_down = download

                        active_conns[cid] = (upload, download)

                        dest_ip = metadata.get("destinationIP") or ""
                        h_flag = resolve_domain_flag(host_name, dest_ip)
                        n_flag = extract_node_flag(node_name)

                        if len(live_snapshot) < 100:
                            live_snapshot.append({
                                "id": cid,
                                "source_ip": source_ip,
                                "host": host_name,
                                "host_flag": h_flag,
                                "node": node_name,
                                "node_flag": n_flag,
                                "group": group_name,
                                "rule": rule_display,
                                "upload": upload,
                                "download": download,
                                "total": upload + download,
                                "start": c.get("start")
                            })

                        if delta_up > 0 or delta_down > 0:
                            key = (today, source_ip, rule_display, node_name, group_name)
                            if key not in buffer:
                                buffer[key] = [0, 0]
                            buffer[key][0] += delta_up
                            buffer[key][1] += delta_down

                            if host_name:
                                d_key = (today, host_name)
                                if d_key not in domain_buffer:
                                    domain_buffer[d_key] = [0, 0]
                                domain_buffer[d_key][0] += delta_up
                                domain_buffer[d_key][1] += delta_down

                    global current_live_conns
                    current_live_conns = live_snapshot

                    dead_ids = set(active_conns.keys()) - current_ids
                    for dead_id in dead_ids:
                        del active_conns[dead_id]

                    now = datetime.datetime.now()
                    if (now - last_flush).total_seconds() >= 5 and (buffer or domain_buffer):
                        conn = get_db()
                        cur = conn.cursor()
                        for (dt, ip, r, n, g), (up_d, down_d) in buffer.items():
                            cur.execute("""
                            INSERT INTO traffic_daily (date, device_ip, rule, node_name, group_name, upload_bytes, download_bytes)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(date, device_ip, rule, node_name, group_name) DO UPDATE SET
                                upload_bytes = upload_bytes + excluded.upload_bytes,
                                download_bytes = download_bytes + excluded.download_bytes
                            """, (dt, ip, r, n, g, up_d, down_d))
                        for (dt, h), (up_d, down_d) in domain_buffer.items():
                            cur.execute("""
                            INSERT INTO traffic_domain_daily (date, host, upload_bytes, download_bytes)
                            VALUES (?, ?, ?, ?)
                            ON CONFLICT(date, host) DO UPDATE SET
                                upload_bytes = upload_bytes + excluded.upload_bytes,
                                download_bytes = download_bytes + excluded.download_bytes
                            """, (dt, h, up_d, down_d))
                        conn.commit()
                        conn.close()
                        buffer.clear()
                        domain_buffer.clear()
                        last_flush = now

        except Exception as e:
            print(f"[Collector 异常] {e}，5 秒后重试...")
            await asyncio.sleep(5)

async def auto_clean_task():
    """定时清理过期数据任务 (每天凌晨 03:00 或启动时检测)"""
    while True:
        try:
            days_str = get_setting("retention_days", "90")
            days = int(days_str) if days_str.isdigit() else 90
            if days > 0:
                cutoff_date = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
                conn = get_db()
                cur = conn.cursor()
                cur.execute("DELETE FROM traffic_daily WHERE date < ?", (cutoff_date,))
                del_count1 = cur.rowcount
                cur.execute("DELETE FROM traffic_domain_daily WHERE date < ?", (cutoff_date,))
                del_count2 = cur.rowcount
                conn.commit()
                if del_count1 > 0 or del_count2 > 0:
                    cur.execute("VACUUM")
                    print(f"[Storage Auto-Clean] 已清理 {days} 天前历史数据 ({cutoff_date} 之前)")
                conn.close()
        except Exception as e:
            print("[Storage Auto-Clean 错误]", e)
        # 每 12 小时检测一次
        await asyncio.sleep(12 * 3600)

@asynccontextmanager
async def lifespan(app: FastAPI):
    t1 = asyncio.create_task(clash_collector_task())
    t2 = asyncio.create_task(clash_traffic_task())
    t3 = asyncio.create_task(auto_clean_task())
    yield
    t1.cancel()
    t2.cancel()
    t3.cancel()

app = FastAPI(title="OpenClash Traffic Analytics", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/favicon.ico")
def favicon():
    return Response(content=SVG_FAVICON, media_type="image/svg+xml")

# ================= 权限认证与访问控制 =================
@app.get("/api/auth/status")
def get_auth_status(request: Request):
    auth_enabled = get_setting("auth_enabled", "0") == "1"
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
    is_authed = (not auth_enabled) or (token in active_tokens)
    return {
        "auth_enabled": auth_enabled,
        "is_authenticated": is_authed
    }

@app.post("/api/auth/login")
def login(data: dict = Body(...)):
    pwd = data.get("password", "")
    stored_pwd = get_setting("auth_password", "")
    if pwd == stored_pwd:
        token = create_token(pwd)
        return {"status": "ok", "token": token}
    return JSONResponse({"status": "error", "message": "密码错误，请重新输入"}, status_code=400)

@app.post("/api/auth/logout")
def logout(request: Request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
    if token in active_tokens:
        active_tokens.remove(token)
    return {"status": "ok"}

@app.post("/api/settings/update_auth")
def update_auth(data: dict = Body(...), authed: bool = Depends(check_auth)):
    enabled = data.get("enabled", False)
    new_password = data.get("new_password", "").strip()

    if enabled:
        if new_password:
            set_setting("auth_password", new_password)
        elif not get_setting("auth_password", ""):
            return JSONResponse({"status": "error", "message": "开启访问控制必须设置密码"}, status_code=400)
        set_setting("auth_enabled", "1")
    else:
        set_setting("auth_enabled", "0")

    return {"status": "ok", "auth_enabled": enabled}

# ================= 数据存储统计与管理 =================
@app.get("/api/settings/storage_info")
def get_storage_info(authed: bool = Depends(check_auth)):
    db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM traffic_daily")
    traffic_rows = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM traffic_domain_daily")
    domain_rows = c.fetchone()[0]
    c.execute("SELECT MIN(date), MAX(date) FROM traffic_daily")
    date_range = c.fetchone()
    conn.close()

    return {
        "db_size_bytes": db_size,
        "traffic_rows": traffic_rows,
        "domain_rows": domain_rows,
        "earliest_date": date_range[0] or "暂无",
        "latest_date": date_range[1] or "暂无",
        "retention_days": int(get_setting("retention_days", "90")),
        "clash_host": get_setting("clash_host", "127.0.0.1"),
        "clash_port": int(get_setting("clash_port", "9090")),
        "clash_secret": get_setting("clash_secret", "")
    }

@app.post("/api/settings/clean_data")
def clean_data(data: dict = Body(...), authed: bool = Depends(check_auth)):
    days = data.get("days", 30)
    clean_all = data.get("clean_all", False)
    conn = get_db()
    c = conn.cursor()

    if clean_all:
        c.execute("DELETE FROM traffic_daily")
        c.execute("DELETE FROM traffic_domain_daily")
        msg = "已清空所有历史流量数据"
    else:
        cutoff = (datetime.date.today() - datetime.timedelta(days=int(days))).isoformat()
        c.execute("DELETE FROM traffic_daily WHERE date < ?", (cutoff,))
        c.execute("DELETE FROM traffic_domain_daily WHERE date < ?", (cutoff,))
        msg = f"已成功清理 {days} 天前 ({cutoff} 之前) 的历史数据"

    conn.commit()
    c.execute("VACUUM")
    conn.close()
    return {"status": "ok", "message": msg}

@app.post("/api/settings/save_clash")
def save_clash_config(data: dict = Body(...), authed: bool = Depends(check_auth)):
    """保存并切换连接的旁路由/OpenClash客户端"""
    host = data.get("host", "127.0.0.1").strip()
    port = str(data.get("port", "9090")).strip()
    secret = data.get("secret", "").strip()
    retention_days = str(data.get("retention_days", "90")).strip()

    # 测试连接
    test_url = f"http://{host}:{port}/version"
    req = urllib.request.Request(test_url)
    if secret:
        req.add_header("Authorization", f"Bearer {secret}")
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            if resp.status != 200:
                return JSONResponse({
                    "status": "error",
                    "message": f"连接测试失败: HTTP {resp.status}，请检查密钥或端口"
                }, status_code=400)
    except urllib.error.HTTPError as he:
        return JSONResponse({
            "status": "error",
            "message": f"连接测试失败: HTTP {he.code}，请检查密钥或端口"
        }, status_code=400)
    except Exception as e:
        return JSONResponse({
            "status": "error",
            "message": f"无法连接目标地址 http://{host}:{port} ({e})，请确认 IP 端口是否正确"
        }, status_code=400)

    # 验证成功，持久化
    set_setting("clash_host", host)
    set_setting("clash_port", port)
    set_setting("clash_secret", secret)
    set_setting("retention_days", retention_days)

    # 触发后台 WebSocket 重新连接
    collector_restart_event.set()

    return {"status": "ok", "message": "连接测试成功，已切换至新的 OpenClash 目标并自动重连！"}

# ================= 业务统计 API (受访问控制保护) =================
@app.get("/api/traffic_realtime")
def get_traffic_realtime(authed: bool = Depends(check_auth)):
    return {
        "current": current_speed,
        "history": list(traffic_history)
    }

@app.get("/api/live")
def get_live(authed: bool = Depends(check_auth)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT ip, name FROM device_alias")
    aliases = {r["ip"]: r["name"] for r in cur.fetchall()}
    conn.close()

    res = []
    for c in current_live_conns:
        item = dict(c)
        item["device_name"] = aliases.get(item["source_ip"], item["source_ip"])
        res.append(item)
    return {"count": len(res), "connections": res}

@app.get("/api/stats")
def get_stats(period: str = "today", device_ip: Optional[str] = None, authed: bool = Depends(check_auth)):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT ip, name FROM device_alias")
    aliases = {r["ip"]: r["name"] for r in cur.fetchall()}

    where_clauses = []
    params = []
    where_domain_clauses = []
    params_domain = []

    today_str = datetime.date.today().isoformat()
    if period == "today":
        where_clauses.append("date = ?")
        params.append(today_str)
        where_domain_clauses.append("date = ?")
        params_domain.append(today_str)
    elif period == "7d":
        start_date = (datetime.date.today() - datetime.timedelta(days=7)).isoformat()
        where_clauses.append("date >= ?")
        params.append(start_date)
        where_domain_clauses.append("date >= ?")
        params_domain.append(start_date)
    elif period == "30d":
        start_date = (datetime.date.today() - datetime.timedelta(days=30)).isoformat()
        where_clauses.append("date >= ?")
        params.append(start_date)
        where_domain_clauses.append("date >= ?")
        params_domain.append(start_date)

    if device_ip:
        where_clauses.append("device_ip = ?")
        params.append(device_ip)

    where_str = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    where_domain_str = ("WHERE " + " AND ".join(where_domain_clauses)) if where_domain_clauses else ""

    cur.execute(f"SELECT COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(download_bytes), 0) FROM traffic_daily {where_str}", params)
    sum_row = cur.fetchone()
    total_up = sum_row[0]
    total_down = sum_row[1]
    total_traffic = total_up + total_down

    cur.execute(f"""
    SELECT device_ip, SUM(upload_bytes) as up, SUM(download_bytes) as down, (SUM(upload_bytes) + SUM(download_bytes)) as total
    FROM traffic_daily
    {where_str}
    GROUP BY device_ip
    ORDER BY total DESC
    """, params)
    devices = [
        {
            "ip": r["device_ip"],
            "name": aliases.get(r["device_ip"], r["device_ip"]),
            "upload": r["up"],
            "download": r["down"],
            "total": r["total"],
            "percent": round(r["total"] / total_traffic * 100, 1) if total_traffic > 0 else 0
        }
        for r in cur.fetchall()
    ]

    cur.execute(f"""
    SELECT node_name, group_name, SUM(upload_bytes) as up, SUM(download_bytes) as down, (SUM(upload_bytes) + SUM(download_bytes)) as total
    FROM traffic_daily
    {where_str}
    GROUP BY node_name
    ORDER BY total DESC
    """, params)
    nodes = [
        {
            "node": r["node_name"],
            "flag": extract_node_flag(r["node_name"]),
            "group": r["group_name"],
            "upload": r["up"],
            "download": r["down"],
            "total": r["total"],
            "percent": round(r["total"] / total_traffic * 100, 1) if total_traffic > 0 else 0
        }
        for r in cur.fetchall()
    ]

    cur.execute(f"""
    SELECT rule, SUM(upload_bytes) as up, SUM(download_bytes) as down, (SUM(upload_bytes) + SUM(download_bytes)) as total
    FROM traffic_daily
    {where_str}
    GROUP BY rule
    ORDER BY total DESC
    LIMIT 30
    """, params)
    rules = [
        {
            "rule": r["rule"],
            "upload": r["up"],
            "download": r["down"],
            "total": r["total"],
            "percent": round(r["total"] / total_traffic * 100, 1) if total_traffic > 0 else 0
        }
        for r in cur.fetchall()
    ]

    cur.execute(f"""
    SELECT host, SUM(upload_bytes) as up, SUM(download_bytes) as down, (SUM(upload_bytes) + SUM(download_bytes)) as total
    FROM traffic_domain_daily
    {where_domain_str}
    GROUP BY host
    ORDER BY total DESC
    LIMIT 200
    """, params_domain)
    domains = [
        {
            "host": r["host"],
            "flag": resolve_domain_flag(r["host"]),
            "upload": r["up"],
            "download": r["down"],
            "total": r["total"],
            "percent": round(r["total"] / total_traffic * 100, 1) if total_traffic > 0 else 0
        }
        for r in cur.fetchall()
    ]

    cur.execute(f"""
    SELECT date, device_ip, rule, node_name, group_name, upload_bytes, download_bytes, (upload_bytes + download_bytes) as total
    FROM traffic_daily
    {where_str}
    ORDER BY total DESC
    LIMIT 200
    """, params)
    details = [
        {
            "date": r["date"],
            "device_ip": r["device_ip"],
            "device_name": aliases.get(r["device_ip"], r["device_ip"]),
            "rule": r["rule"],
            "node": r["node_name"],
            "node_flag": extract_node_flag(r["node_name"]),
            "group": r["group_name"],
            "upload": r["upload_bytes"],
            "download": r["download_bytes"],
            "total": r["total"]
        }
        for r in cur.fetchall()
    ]

    conn.close()

    return {
        "summary": {
            "period": period,
            "total_traffic": total_traffic,
            "total_up": total_up,
            "total_down": total_down,
            "device_count": len(devices),
            "node_count": len(nodes),
            "domain_count": len(domains)
        },
        "devices": devices,
        "nodes": nodes,
        "rules": rules,
        "domains": domains,
        "details": details
    }

@app.post("/api/alias")
def set_alias(data: dict = Body(...), authed: bool = Depends(check_auth)):
    ip = data.get("ip")
    name = data.get("name")
    if not ip or not name:
        return JSONResponse({"status": "error", "message": "IP和名称不能为空"}, status_code=400)
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO device_alias (ip, name, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(ip) DO UPDATE SET name = excluded.name, updated_at = datetime('now')
    """, (ip, name))
    conn.commit()
    conn.close()
    return {"status": "success", "ip": ip, "name": name}

@app.get("/", response_class=HTMLResponse)
def index_page():
    for p in ["/app/templates/index.html", "/app/index.html", "templates/index.html", "index.html"]:
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return f.read()
    return "<h1>index.html not found</h1>"

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=WEB_PORT)
