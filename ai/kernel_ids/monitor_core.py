import asyncio
import os
import psutil
import secrets
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from psycopg2 import pool

app = FastAPI(title="XDP Infrastructure Real-Time Monitor")

# ЖЕСТКАЯ ПРИВЯЗКА К IP ВАШЕГО СЕРВЕРА ДЛЯ СНЯТИЯ БЛОКИРОВОК CORS
SERVER_IP = "45.9.15.253"

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        f"http://{SERVER_IP}:8005",
        f"https://{SERVER_IP}:8005",
        "http://localhost:8005"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

security = HTTPBasic()
SECURITY_USER = "admin"
SECURITY_PASS = "kernel_secure_2026"

db_conf = "dbname=ids_db user=postgres password=ids_pass host=localhost"
db_pool = pool.ThreadedConnectionPool(1, 5, db_conf)

GLOBAL_SYSTEM_STATE = {
    "cpu": 0.0,
    "ram": 0.0,
    "disk": 0.0,
    "interfaces": {},
    "security": {"total_blocks": 0, "total_whitelist": 0, "last_events_count_5m": 0},
    "services": {"dnsmasq": "UNKNOWN", "openvpn": "UNKNOWN", "postgresql": "UNKNOWN"}
}

def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    is_user_correct = secrets.compare_digest(credentials.username, SECURITY_USER)
    is_pass_correct = secrets.compare_digest(credentials.password, SECURITY_PASS)
    if not (is_user_correct and is_pass_correct):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный логин или пароль мониторинга",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

async def async_get_sys_cmd(cmd_args: list) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip()
    except:
        return "error"

async def background_metrics_worker():
    global GLOBAL_SYSTEM_STATE
    last_net_io = {}
    
    try:
        init_io = psutil.net_io_counters(pernic=True)
        t_init = asyncio.get_event_loop().time()
        for iface, io in init_io.items():
            last_net_io[iface] = (io.bytes_sent, io.bytes_recv, t_init)
    except:
        pass

    psutil.cpu_percent(interval=None)
    db_tick = 0

    while True:
        await asyncio.sleep(1)
        db_tick += 1
        
        try:
            cpu = float(psutil.cpu_percent(interval=None))
            ram = float(psutil.virtual_memory().percent)
            disk = float(psutil.disk_usage('/').percent)
        except:
            cpu, ram, disk = 0.0, 0.0, 0.0

        interfaces = {}
        try:
            net_io_now = psutil.net_io_counters(pernic=True)
            ifaces_list = os.listdir('/sys/class/net/')
            all_addrs = psutil.net_if_addrs()
        except:
            net_io_now, ifaces_list, all_addrs = {}, [], {}
            
        curr_time = asyncio.get_event_loop().time()

        for iface in ifaces_list:
            if iface == 'lo': continue
            try:
                state_path = f'/sys/class/net/{iface}/operstate'
                state = "UNKNOWN"
                if os.path.exists(state_path):
                    with open(state_path, 'r') as f:
                        state = f.read().strip().upper()
                
                ip_addr = "No IP"
                if iface in all_addrs:
                    for addr in all_addrs[iface]:
                        if addr.family == 2:
                            ip_addr = str(addr.address)
                            break

                io = net_io_now.get(iface)
                speed_tx, speed_rx = 0.0, 0.0
                
                if io and iface in last_net_io:
                    prev_sent, prev_recv, prev_time = last_net_io[iface]
                    time_delta = curr_time - prev_time
                    if time_delta > 0:
                        speed_tx = round(((io.bytes_sent - prev_sent) / 1024) / time_delta, 2)
                        speed_rx = round(((io.bytes_recv - prev_recv) / 1024) / time_delta, 2)
                
                if io:
                    last_net_io[iface] = (io.bytes_sent, io.bytes_recv, curr_time)

                interfaces[iface] = {
                    "state": str(state),
                    "ip": ip_addr,
                    "packets_sent": int(io.packets_sent) if io else 0,
                    "packets_recv": int(io.packets_recv) if io else 0,
                    "errors": int(io.errin + io.errout) if io else 0,
                    "speed_tx": speed_tx,
                    "speed_rx": speed_rx
                }
            except:
                pass

        if db_tick >= 3:
            db_tick = 0
            conn = None
            try:
                conn = db_pool.getconn()
                cur = conn.cursor()
                
                cur.execute("SELECT COUNT(*) FROM managed_lists WHERE list_type = 'BLACK';")
                res_b = cur.fetchone()
                GLOBAL_SYSTEM_STATE["security"]["total_blocks"] = int(res_b[0]) if res_b else 0
                
                cur.execute("SELECT COUNT(*) FROM managed_lists WHERE list_type = 'WHITE';")
                res_w = cur.fetchone()
                GLOBAL_SYSTEM_STATE["security"]["total_whitelist"] = int(res_w[0]) if res_w else 0
                
                cur.execute("SELECT COUNT(*) FROM security_events WHERE created_at > NOW() - INTERVAL '5 minute';")
                res_e = cur.fetchone()
                GLOBAL_SYSTEM_STATE["security"]["last_events_count_5m"] = int(res_e[0]) if res_e else 0
                
                cur.close()
            except Exception as e:
                print(f"[-] Ошибка фонового чтения БД: {e}")
            finally:
                if conn:
                    db_pool.putconn(conn)

            for srv in ["dnsmasq", "postgresql"]:
                res = await async_get_sys_cmd(["systemctl", "is-active", srv])
                GLOBAL_SYSTEM_STATE["services"][srv] = "ACTIVE" if res == "active" else "STOPPED"
                
            res_vpn = await async_get_sys_cmd(["systemctl", "is-active", "openvpn@server"])
            GLOBAL_SYSTEM_STATE["services"]["openvpn"] = "ACTIVE" if res_vpn == "active" else "STOPPED"

        GLOBAL_SYSTEM_STATE["cpu"] = cpu
        GLOBAL_SYSTEM_STATE["ram"] = ram
        GLOBAL_SYSTEM_STATE["disk"] = disk
        GLOBAL_SYSTEM_STATE["interfaces"] = interfaces

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(background_metrics_worker())

@app.get("/api/metrics")
async def get_metrics_api(username: str = Depends(authenticate_user)):
    return GLOBAL_SYSTEM_STATE

@app.get("/", response_class=HTMLResponse)
def get_monitor_dashboard(username: str = Depends(authenticate_user)):
    if os.path.exists("dashboard.html"):
        with open("dashboard.html", "r", encoding="utf-8") as f:
            return f.read()
    raise HTTPException(status_code=404, detail="Файл dashboard.html не найден")
