
#!/bin/bash
set -e

# 1. Запись конфигурационного файла сетевой карты
cp /root/ai/kernel_ids/ids.conf /tmp/ids-package/opt/kernel_ids/ids.conf 2>/dev/null || echo 'INTERFACE="ens3"' > /tmp/ids-package/opt/kernel_ids/ids.conf

# 2. Копирование кода фильтра ядра XDP
cp /root/ai/kernel_ids/xdp_filter.c /tmp/ids-package/opt/kernel_ids/xdp_filter.c

# 3. ГЕНЕРАЦИЯ УНИВЕРСАЛЬНОГО ДВИЖКА IDS/IPS (main.py)
cat << 'EOF' > /tmp/ids-package/opt/kernel_ids/main.py
import socket, struct, threading, queue, ctypes, secrets, psycopg2, numpy as np
from fastapi import FastAPI, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from bcc import BPF
from sklearn.ensemble import IsolationForest

app = FastAPI(title="XDP Kernel IDS/IPS")
security = HTTPBasic()
SECURITY_USER, SECURITY_PASS = "admin", "kernel_secure_2026"

def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    if not (secrets.compare_digest(credentials.username, SECURITY_USER) and secrets.compare_digest(credentials.password, SECURITY_PASS)):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return credentials.username

# Динамическое чтение имени интерфейса из конфигурационного файла ids.conf
with open("ids.conf", "r") as f:
    INTERFACE = f.read().split("=")[1].replace('"', '').strip()

db_conf = "dbname=ids_db user=postgres password=ids_pass host=localhost"
conn = psycopg2.connect(db_conf); cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS security_events (id SERIAL PRIMARY KEY, src_ip TEXT, dport INT, action TEXT, reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);")
cursor.execute("CREATE TABLE IF NOT EXISTS managed_lists (src_ip TEXT PRIMARY KEY, list_type TEXT CHECK (list_type IN ('WHITE', 'BLACK')), updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);")
conn.commit()

bpf_ctx = BPF(src_file="xdp_filter.c")
bpf_fn = bpf_ctx.load_func("xdp_fw_router", BPF.XDP)
bpf_ctx.attach_xdp(INTERFACE, bpf_fn, 0)
ai_queue = queue.Queue(maxsize=10000)

def u32_to_ip(n): return socket.inet_ntoa(struct.pack("<I", n))
def ip_to_u32(s): return struct.unpack("<I", socket.inet_aton(s))[0]

def trigger_auto_block(ip_str, port, reason):
    try:
        bpf_ctx["blacklist_map"][ctypes.c_uint32(ip_to_u32(ip_str))] = ctypes.c_uint8(1)
        l_conn = psycopg2.connect(db_conf); l_cur = l_conn.cursor()
        l_cur.execute("INSERT INTO managed_lists (src_ip, list_type) VALUES (%s, 'BLACK') ON CONFLICT (src_ip) DO UPDATE SET list_type = 'BLACK';", (ip_str,))
        l_cur.execute("INSERT INTO security_events (src_ip, dport, action, reason) VALUES (%s, %s, 'BLOCKED', %s)", (ip_str, port, reason))
        l_conn.commit(); l_cur.close(); l_conn.close()
    except Exception as e: print(f"[-] Block Error: {e}")

def ai_worker_thread():
    ai_model = IsolationForest(contamination=0.02, random_state=42); traffic_buffer = []
    while True:
        try:
            ip_str, dport, sport = ai_queue.get()
            traffic_buffer.append([dport, sport])
            if len(traffic_buffer) >= 50:
                ai_model.fit(np.array(traffic_buffer))
                if ai_model.predict(np.array(traffic_buffer))[-1] == -1:
                    trigger_auto_block(ip_str, dport, "AI Anomaly Detected")
                traffic_buffer = traffic_buffer[-20:]
            ai_queue.task_done()
        except: pass

@app.on_event("startup")
def start_tasks():
    threading.Thread(target=ai_worker_thread, daemon=True).start()
    threading.Thread(target=lambda: bpf_ctx["events"].open_perf_buffer(lambda c, d, s: ai_queue.put_nowait((u32_to_ip(bpf_ctx["events"].event(d).src_ip), bpf_ctx["events"].event(d).dport, bpf_ctx["events"].event(d).sport)) if not ai_queue.full() else None, page_cnt=256) or [bpf_ctx.perf_buffer_poll() for _ in iter(int, 1)], daemon=True).start()

@app.get("/", response_class=HTMLResponse)
def dashboard(username: str = Depends(authenticate_user)):
    return "<html><body><h1>🛡️ Core IPS Active</h1></body></html>"
EOF

# 4. КОПИРОВАНИЕ ОСТАЛЬНЫХ ПОДСИСТЕМ (counter.py, gateway.py)
cp /root/ai/kernel_ids/counter.py /tmp/ids-package/opt/kernel_ids/counter.py
cp /root/ai/kernel_ids/gateway.py /tmp/ids-package/opt/kernel_ids/gateway.py

# 5. ГЕНЕРАЦИЯ УНИВЕРСАЛЬНОГО КЭШИРУЮЩЕГО МОНИТОРИНГА (monitor_core.py)
cat << 'EOF' > /tmp/ids-package/opt/kernel_ids/monitor_core.py
import asyncio, os, psutil, secrets, psycopg2
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from psycopg2 import pool

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
security = HTTPBasic()
SECURITY_USER, SECURITY_PASS = "admin", "kernel_secure_2026"
db_conf = "dbname=ids_db user=postgres password=ids_pass host=localhost"
db_pool = pool.ThreadedConnectionPool(1, 5, db_conf)
GLOBAL_SYSTEM_STATE = {"cpu": 0.0, "ram": 0.0, "disk": 0.0, "interfaces": {}, "security": {"total_blocks": 0, "total_whitelist": 0, "last_events_count_5m": 0}, "services": {"dnsmasq": "UNKNOWN", "postgresql": "UNKNOWN"}}

async def background_metrics_worker():
    global GLOBAL_SYSTEM_STATE
    last_net_io = {}
    while True:
        await asyncio.sleep(1)
        conn = None
        try:
            conn = db_pool.getconn(); cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM managed_lists WHERE list_type = 'BLACK';")
            GLOBAL_SYSTEM_STATE["security"]["total_blocks"] = int(cur.fetchone()[0])
            cur.close()
        except: pass
        finally:
            if conn: db_pool.putconn(conn)
            
        interfaces = {}
        try:
            net_io_now = psutil.net_io_counters(pernic=True)
            all_addrs = psutil.net_if_addrs()
            for iface in os.listdir('/sys/class/net/'):
                if iface == 'lo': continue
                ip_addr = "No IP"
                if iface in all_addrs:
                    for addr in all_addrs[iface]:
                        if addr.family == 2: ip_addr = str(addr.address); break
                io = net_io_now.get(iface)
                interfaces[iface] = {"state": "UP", "ip": ip_addr, "packets_sent": io.packets_sent if io else 0, "packets_recv": io.packets_recv if io else 0, "errors": io.errin+io.errout if io else 0, "speed_tx": 0.0, "speed_rx": 0.0}
        except: pass
        GLOBAL_SYSTEM_STATE.update({"cpu": float(psutil.cpu_percent()), "ram": float(psutil.virtual_memory().percent), "disk": float(psutil.disk_usage('/').percent), "interfaces": interfaces})

@app.on_event("startup")
async def startup_event(): asyncio.create_task(background_metrics_worker())
@app.get("/api/metrics")
async def get_metrics_api(username: str = Depends(security)): return GLOBAL_SYSTEM_STATE
@app.get("/", response_class=HTMLResponse)
def get_monitor_dashboard(username: str = Depends(security)):
    with open("dashboard.html", "r", encoding="utf-8") as f: return f.read()
EOF

# 6. ГЕНЕРАЦИЯ ФАЙЛОВ СЛУЖБ SYSTEMD
cat << 'EOF' > /tmp/ids-package/etc/systemd/system/xdp-main.service
[Unit]
Description=XDP Core IDS/IPS Service
After=network.target postgresql.service
[Service]
Type=simple
User=root
WorkingDirectory=/opt/kernel_ids
ExecStart=/usr/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
[Install]
WantedBy=multi-user.target
EOF

cat << 'EOF' > /tmp/ids-package/etc/systemd/system/xdp-counter.service
[Unit]
Description=XDP AI Counter-Attack Engine
After=xdp-main.service
[Service]
Type=simple
User=root
WorkingDirectory=/opt/kernel_ids
ExecStart=/usr/bin/uvicorn counter:app --host 0.0.0.0 --port 8001
Restart=always
[Install]
WantedBy=multi-user.target
EOF

cat << 'EOF' > /tmp/ids-package/etc/systemd/system/xdp-gateway.service
[Unit]
Description=XDP Gateway Router Controls
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/opt/kernel_ids
ExecStart=/usr/bin/uvicorn gateway:app --host 0.0.0.0 --port 8002
Restart=always
[Install]
WantedBy=multi-user.target
EOF

cat << 'EOF' > /tmp/ids-package/etc/systemd/system/xdp-monitor.service
[Unit]
Description=XDP Infrastructure System Monitor
After=postgresql.service
[Service]
Type=simple
User=root
WorkingDirectory=/opt/kernel_ids
ExecStart=/usr/bin/uvicorn monitor_core:app --host 0.0.0.0 --port 8005
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# 7. СБОРКА АРХИВА ПО ПРАВИЛАМ DEBIAN 13
find /tmp/ids-package/ -type d -exec chmod 755 {} +
find /tmp/ids-package/ -type f -exec chmod 644 {} +
chmod 755 /tmp/ids-package/DEBIAN/postinst

echo "[+] Сборка универсального бинарного пакета..."
dpkg-deb --root-owner-group -Z gzip --build /tmp/ids-package /tmp/kernel-xdp-ips_1.0.3_amd64.deb
chmod 644 /tmp/kernel-xdp-ips_1.0.3_amd64.deb

echo "[+] Проверка формата архива:"
file /tmp/kernel-xdp-ips_1.0.3_amd64.deb
echo "[+] Готово!"
