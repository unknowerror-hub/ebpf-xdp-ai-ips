import socket, struct, threading, os, subprocess, secrets, re
from fastapi import FastAPI, Form, Depends, HTTPException, status, Response
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from psycopg2 import pool

app = FastAPI(title="XDP Gateway Router Controls")
security = HTTPBasic()

# --- CONFIG & CREDENTIALS ---
SECURITY_USER = "admin"
SECURITY_PASS = "kernel_secure_2026"

GW_STATUS = {
    "wan_status": "ONLINE (Primary)", "vpn_status": "DISCONNECTED",
    "dhcp_status": "UNKNOWN", "dhcp_leases": 0, "active_routes": 2
}
status_lock = threading.Lock()
db_conf = "dbname=ids_db user=postgres password=ids_pass host=localhost"
db_pool = pool.ThreadedConnectionPool(1, 5, db_conf)

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    u_ok = secrets.compare_digest(credentials.username, SECURITY_USER)
    p_ok = secrets.compare_digest(credentials.password, SECURITY_PASS)
    if not (u_ok and p_ok):
        raise HTTPException(401, "Unauthorized", {"WWW-Authenticate": "Basic"})
    return credentials.username

# --- СИСТЕМНЫЕ ФУНКЦИИ ВЗАИМОДЕЙСТВИЯ С ОС LINUX ---
def run_sys_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return res.returncode == 0, res.stdout.strip()
    except:
        return False, "Execution Error"

def get_network_interfaces():
    interfaces = []
    try:
        ifaces = os.listdir('/sys/class/net/')
        for iface in ifaces:
            if iface == 'lo': continue
            _, ip_out = run_sys_cmd(f"ip -4 addr show {iface}")
            ip_match = re.search(r'inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', ip_out)
            ip = ip_match.group(1) if ip_match else "Нет IP"
            with open(f'/sys/class/net/{iface}/operstate', 'r') as f:
                state = f.read().strip().upper()
            interfaces.append({"name": iface, "ip": ip, "state": state})
    except Exception as e:
        print(f"[-] Ошибка сканирования интерфейсов: {e}")
    return interfaces

def toggle_ip_forwarding(enable=True):
    val = "1" if enable else "0"
    run_sys_cmd(f"echo {val} > /proc/sys/net/ipv4/ip_forward")

def apply_nat_rules(wan_iface, lan_network):
    run_sys_cmd(f"iptables -t nat -A POSTROUTING -s {lan_network} -o {wan_iface} -j MASQUERADE")
    run_sys_cmd("iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")

# --- ФУНКЦИИ АВТОНОМНОГО ОТКАЗОУСТОЙЧИВОГО ИНТЕРНЕТА (FAILOVER) ---
def internet_failover_worker():
    while True:
        ok1, _ = run_sys_cmd("ping -c 2 -W 2 8.8.8.8")
        with status_lock:
            if ok1:
                if GW_STATUS["wan_status"] != "ONLINE (Primary)":
                    run_sys_cmd("ip route replace default via 192.168.1.1 dev eth0")
                    GW_STATUS["wan_status"] = "ONLINE (Primary)"
            else:
                if GW_STATUS["wan_status"] == "ONLINE (Primary)":
                    run_sys_cmd("ip route replace default via 192.168.2.1 dev eth1")
                    GW_STATUS["wan_status"] = "BACKUP LINK (Active)"
        threading.Event().wait(10)
# --- РАСШИРЕННАЯ НАСТРОЙКА DHCP/DNS ---
def get_service_status(service_name):
    ok, _ = run_sys_cmd(f"systemctl is-active {service_name}")
    return "АКТИВЕН" if ok else "ОСТАНОВЛЕН"

def write_dnsmasq_config(lan_iface, dhcp_range, dns_upstream, static_leases=""):
    cfg = f"""interface={lan_iface}
dhcp-range={dhcp_range},12h
server={dns_upstream}
cache-size=1500
log-queries
"""
    if static_leases:
        for line in static_leases.splitlines():
            if line.strip(): cfg += f"dhcp-host={line.strip()}\n"
    try:
        with open("/etc/dnsmasq.d/gateway.conf", "w") as f: f.write(cfg)
        return True
    except: return False

# --- API ЭНДПОИНТЫ УПРАВЛЕНИЯ ---
@app.post("/api/gateway/interface/configure")
def configure_interface(iface: str = Form(...), ip: str = Form(...), gateway: str = Form(None), u=Depends(authenticate)):
    run_sys_cmd(f"ip addr flush dev {iface}")
    success, _ = run_sys_cmd(f"ip addr add {ip} dev {iface}")
    if success:
        run_sys_cmd(f"ip link set {iface} up")
        if gateway: run_sys_cmd(f"ip route add default via {gateway} dev {iface}")
    return Response(status_code=303, headers={"Location": "/"})

@app.post("/api/gateway/dhcp/configure")
def configure_dhcp(
    wan: str = Form(...), lan_net: str = Form(...), 
    dhcp: str = Form(...), dns: str = Form(...), 
    statics: str = Form(None), u=Depends(authenticate)
):
    toggle_ip_forwarding(True)
    apply_nat_rules(wan, lan_net)
    write_dnsmasq_config(wan, dhcp, dns, statics)
    run_sys_cmd("systemctl restart dnsmasq")
    return Response(status_code=303, headers={"Location": "/"})

@app.post("/api/gateway/dhcp/control")
def control_dhcp_service(action: str = Form(...), u=Depends(authenticate)):
    cmd = "start" if action == "start" else "stop"
    run_sys_cmd(f"systemctl {cmd} dnsmasq")
    return Response(status_code=303, headers={"Location": "/"})

@app.post("/api/gateway/vpn")
def control_vpn(action: str = Form(...), u=Depends(authenticate)):
    with status_lock:
        if action == "start":
            success, _ = run_sys_cmd("systemctl start openvpn@server")
            GW_STATUS["vpn_status"] = "RUNNING" if success else "FAILED"
        elif action == "stop":
            run_sys_cmd("systemctl stop openvpn@server")
            GW_STATUS["vpn_status"] = "DISCONNECTED"
    return Response(status_code=303, headers={"Location": "/"})

# --- ВЕБ-ИНТЕРФЕЙС РОУТЕРА (ПОРТ 8002) ---
@app.get("/", response_class=HTMLResponse)
def gateway_dashboard(u=Depends(authenticate)):
    _, leases = run_sys_cmd("wc -l < /var/lib/misc/dnsmasq.leases")
    dhcp_state = get_service_status("dnsmasq")
    try:
        with status_lock: GW_STATUS["dhcp_leases"] = int(leases) if dhcp_state == "АКТИВЕН" else 0
    except: pass
    
    try:
        conn = db_pool.getconn(); cur = conn.cursor()
        cur.execute("SELECT src_ip, action, reason FROM security_events LIMIT 3;")
        alerts = cur.fetchall(); db_pool.putconn(conn)
    except: alerts = []
    
    alert_rows = "".join([f"<tr><td>{a[0]}</td><td style='color:red;'>{a[1]}</td><td>{a[2]}</td></tr>" for a in alerts])
    iface_rows = "".join([f"<tr><td><b>{i['name']}</b></td><td><code>{i['ip']}</code></td><td><span style='color:{'#2ecc71' if i['state']=='UP' else '#e74c3c'};font-weight:bold;'>{i['state']}</span></td><td><form action='/api/gateway/interface/configure' method='post' style='margin:0; display:flex; gap:5px;'><input type='hidden' name='iface' value='{i['name']}'><input type='text' name='ip' placeholder='192.168.1.1/24' required style='padding:4px; width:120px;'><input type='text' name='gateway' placeholder='Шлюз' style='padding:4px; width:80px;'><button type='submit' style='padding:4px; background:#3498db;'>Задать</button></form></td></tr>" for i in get_network_interfaces()])
    dhcp_btn = f'<form action="/api/gateway/dhcp/control" method="post" style="display:inline;"><input type="hidden" name="action" value="{"stop" if dhcp_state=="АКТИВЕН" else "start"}"><button style="background:{"#e74c3c" if dhcp_state=="АКТИВЕН" else "#2ecc71"};">{"Остановить DHCP" if dhcp_state=="АКТИВЕН" else "Запустить DHCP"}</button></form>'

    return f"""
    <html><head><title>Gateway Core</title><style>
        body {{ font-family: sans-serif; background: #f4f6f9; color: #333; margin: 25px; }}
        .box {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 20px; }}
        .badge {{ background: #2ecc71; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
        .grid {{ display: flex; gap: 20px; }} table {{ width:100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; border-bottom: 1px solid #ddd; text-align: left; font-size:13px; }} th {{ background: #35495e; color: white; }}
        input, select, textarea, button {{ padding: 8px; margin-top: 5px; border-radius: 4px; border: 1px solid #ccc; }}
        button {{ background: #34495e; color: white; border: none; cursor: pointer; font-weight: bold; }}
    </style></head><body>
        <h1>🌐 Панель Управления Сетевым Шлюзом и Маршрутизацией</h1>
        <div class="box">
            Интернет-Failover: <span class="badge">{GW_STATUS['wan_status']}</span> | 
            Шлюзовой VPN: <span class="badge" style="background:#3498db;">{GW_STATUS['vpn_status']}</span> | 
            DHCP Сервер: <span class="badge" style="background:{'#2ecc71' if dhcp_state=='АКТИВЕН' else '#e74c3c'};">{dhcp_state}</span> |
            Активных аренд: <b>{GW_STATUS['dhcp_leases']}</b>
            <div style="margin-top:10px;">{dhcp_btn}</div>
        </div>
        <div class="box">
            <h2>🎛️ Настройки всех сетевых интерфейсов Linux</h2>
            <table><tr><th>Интерфейс</th><th>Текущий IP (CIDR)</th><th>Статус</th><th>Конфигурация (Новый IP и Маска)</th></tr>{iface_rows}</table>
        </div>
        <div class="grid">
            <div class="box" style="flex: 1.2;">
                <h2>Расширенная настройка DHCP & DNS</h2>
                <form action="/api/gateway/dhcp/configure" method="post">
                    <label>Внешний интерфейс (WAN):</label><br><input type="text" name="wan" value="eth0" style="width:100%;"><br>
                    <label>Локальная сеть (LAN Network):</label><br><input type="text" name="lan_net" value="192.168.1.0/24" style="width:100%;"><br>
                    <label>Диапазон DHCP пула:</label><br><input type="text" name="dhcp" value="192.168.1.50,192.168.1.250" style="width:100%;"><br>
                    <label>DNS Upstream сервер:</label><br><input type="text" name="dns" value="1.1.1.1" style="width:100%;"><br>
                    <label>Статический DHCP (Формат: MAC,IP,Имя):</label><br>
                    <textarea name="statics" rows="3" placeholder="00:11:22:33:44:55,192.168.1.10,server" style="width:100%; font-family:monospace; font-size:12px;"></textarea>
                    <button type="submit" style="background:#2ecc71; width:100%; margin-top:10px;">Применить и перезапустить</button>
                </form>
            </div>
            <div class="box" style="flex: 1;">
                <h2>Шлюзовой VPN (OpenVPN)</h2>
                <form action="/api/gateway/vpn" method="post" style="display:inline;"><input type="hidden" name="action" value="start"><button style="background:#2ecc71; width:100%; margin-bottom:10px;">Старт OpenVPN Server</button></form>
                <form action="/api/gateway/vpn" method="post" style="display:inline;"><input type="hidden" name="action" value="stop"><button style="background:#e74c3c; width:100%;">Остановить OpenVPN</button></form>
                <h3 style="margin-top:20px;">XDP/IPS Блокировки</h3>
                <table><tr><th>IP Нарушителя</th><th>Действие</th><th>Причина</th></tr>{alert_rows or "<tr><td colspan='3'>Стабильно</td></tr>"}</table>
            </div>
        </div>
    </body></html>
    """

@app.on_event("startup")
def startup_gateway_services():
    threading.Thread(target=internet_failover_worker, daemon=True).start()
