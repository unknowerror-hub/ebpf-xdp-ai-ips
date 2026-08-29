# ==============================================================================
# ЧАСТЬ 1: ИМПОРТЫ, НАСТРОЙКИ, БАЗА ДАННЫХ И GEOIP
# ==============================================================================
import socket
import struct
import threading
import queue
import ctypes
import secrets
import numpy as np
from fastapi import FastAPI, Form, Depends, HTTPException, status, Query
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from bcc import BPF
import psycopg2
from sklearn.ensemble import IsolationForest
import geoip2.database

app = FastAPI(title="XDP Kernel IDS/IPS")
security = HTTPBasic()

SECURITY_USER = "admin"
SECURITY_PASS = "kernel_secure_2026"

def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    is_user_correct = secrets.compare_digest(credentials.username, SECURITY_USER)
    is_pass_correct = secrets.compare_digest(credentials.password, SECURITY_PASS)
    if not (is_user_correct and is_pass_correct):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный логин или пароль",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# Инициализация конфигурации интерфейса
with open("ids.conf", "r") as f:
    config_content = f.read()
    INTERFACE = config_content.split("=")[1].replace('"', '').strip()

db_conf = "dbname=ids_db user=postgres password=ids_pass host=localhost"
conn = psycopg2.connect(db_conf)
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id SERIAL PRIMARY KEY, src_ip TEXT, dport INT, action TEXT, reason TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS managed_lists (
        src_ip TEXT PRIMARY KEY, list_type TEXT CHECK (list_type IN ('WHITE', 'BLACK')), updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")
conn.commit()
cursor.close()
conn.close()

# Загрузка базы данных GeoIP
try:
    reader_geo = geoip2.database.Reader('GeoLite2-Country.mmdb')
except Exception as e:
    print(f"[-] Предупреждение: Не удалось загрузить GeoLite2-Country.mmdb: {e}")
    reader_geo = None

def get_country_by_ip(ip_str):
    if not reader_geo or ip_str in ["0.0.0.0", "127.0.0.1"]:
        return "Local/Unknown"
    try:
        response = reader_geo.country(ip_str)
        return response.country.iso_code if response.country.iso_code else "Unknown"
    except Exception:
        return "Unknown"
# ==============================================================================
# ЧАСТЬ 2: ВЗАИМОДЕЙСТВИЕ С eBPF/XDP И ИИ-АНАЛИТИКА
# ==============================================================================
bpf_ctx = BPF(src_file="xdp_filter.c")
bpf_fn = bpf_ctx.load_func("xdp_fw_router", BPF.XDP)
bpf_ctx.attach_xdp(INTERFACE, bpf_fn, 0)

def u32_to_ip(ip_num):
    return socket.inet_ntoa(struct.pack("<I", ip_num))

def ip_to_u32(ip_str):
    return struct.unpack("<I", socket.inet_aton(ip_str))[0]

def restore_lists_from_db():
    print("[SYSTEM-IDS] Начало восстановления списков из PostgreSQL в ядро eBPF...")
    try:
        local_conn = psycopg2.connect(db_conf)
        local_cursor = local_conn.cursor()
        local_cursor.execute("SELECT src_ip, list_type FROM managed_lists;")
        rows = local_cursor.fetchall()
        
        white_count, black_count = 0, 0
        for src_ip, list_type in rows:
            try:
                key = ctypes.c_uint32(ip_to_u32(src_ip))
                val = ctypes.c_uint8(1)
                if list_type == 'WHITE':
                    bpf_ctx["whitelist_map"][key] = val
                    white_count += 1
                elif list_type == 'BLACK':
                    bpf_ctx["blacklist_map"][key] = val
                    black_count += 1
            except Exception as e:
                print(f"[-] Ошибка загрузки IP {src_ip}: {e}")
        local_cursor.close()
        local_conn.close()
        print(f"[SYSTEM-IDS] Списки восстановлены: Белый ({white_count}), Черный ({black_count})")
    except Exception as e:
        print(f"[-] Ошибка инициализации правил из БД: {e}")

def trigger_auto_block(ip_str, port, reason):
    try:
        key = ctypes.c_uint32(ip_to_u32(ip_str))
        bpf_ctx["blacklist_map"][key] = ctypes.c_uint8(1)
        
        local_conn = psycopg2.connect(db_conf)
        local_cursor = local_conn.cursor()
        local_cursor.execute("""
            INSERT INTO managed_lists (src_ip, list_type, updated_at) VALUES (%s, 'BLACK', CURRENT_TIMESTAMP)
            ON CONFLICT (src_ip) DO UPDATE SET list_type = 'BLACK', updated_at = CURRENT_TIMESTAMP;
        """, (ip_str,))
        local_cursor.execute(
            "INSERT INTO security_events (src_ip, dport, action, reason) VALUES (%s, %s, 'BLOCKED', %s)",
            (ip_str, port, reason)
        )
        local_conn.commit()
        local_cursor.close()
        local_conn.close()
        print(f"[SYSTEM-IDS] IP {ip_str} заблокирован. Причина: {reason}")
    except Exception as e:
        print(f"[-] Ошибка автоблокировки: {e}")

ai_queue = queue.Queue(maxsize=10000)

def ai_worker_thread():
    ai_model = IsolationForest(contamination=0.02, random_state=42)
    traffic_buffer = []
    while True:
        try:
            ip_str, dport, sport = ai_queue.get()
            traffic_buffer.append([dport, sport])
            if len(traffic_buffer) >= 50:
                data_matrix = np.array(traffic_buffer)
                ai_model.fit(data_matrix)
                if ai_model.predict(data_matrix)[-1] == -1:
                    trigger_auto_block(ip_str, dport, "AI Anomaly: Async Port Scan / Flood Detected")
                traffic_buffer = traffic_buffer[-20:]
            ai_queue.task_done()
        except Exception as e:
            print(f"[-] Ошибка ИИ-аналитики: {e}")

def packet_callback(cpu, data, size):
    try:
        event = bpf_ctx["events"].event(data)
        ip_str = u32_to_ip(event.src_ip)
        if not ai_queue.full():
            ai_queue.put_nowait((ip_str, event.dport, event.sport))
    except Exception: pass

def run_ebpf_polling():
    bpf_ctx["events"].open_perf_buffer(packet_callback, page_cnt=256)
    while True:
        try: bpf_ctx.perf_buffer_poll()
        except Exception: break

@app.on_event("startup")
def start_background_tasks():
    restore_lists_from_db()
    threading.Thread(target=ai_worker_thread, daemon=True).start()
    threading.Thread(target=run_ebpf_polling, daemon=True).start()
# ==============================================================================
# ЧАСТЬ 3: ВЕБ-ИНТЕРФЕЙС ДАШБОРДА И РОУТЫ ДЕЙСТВИЙ (ИНТЕГРАЦИЯ СЕРВИСОВ)
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
def dashboard(username: str = Depends(authenticate_user), search_ip: str = Query(None)):
    local_conn = psycopg2.connect(db_conf)
    local_cursor = local_conn.cursor()
    if search_ip:
        local_cursor.execute("SELECT created_at, src_ip, dport, action, reason FROM security_events WHERE src_ip LIKE %s ORDER BY created_at DESC LIMIT 50;", (f"%{search_ip.strip()}%",))
    else:
        local_cursor.execute("SELECT created_at, src_ip, dport, action, reason FROM security_events ORDER BY created_at DESC LIMIT 30;")
    events = local_cursor.fetchall()
    
    blocked_ips = [u32_to_ip(k.value) for k, v in bpf_ctx["blacklist_map"].items()]
    whitelisted_ips = [u32_to_ip(k.value) for k, v in bpf_ctx["whitelist_map"].items()]
    
    table_rows = "".join([f"<tr><td>{e[0]}</td><td><b>{e[1]}</b> <span style='font-size:11px;color:#7f8c8d;'>({get_country_by_ip(e[1])})</span></td><td>{e[2]}</td><td><span style='color:{'red' if e[3] in ['BLOCKED','BANNED'] else 'orange' if e[3]=='CLEARED' else 'green'}'>{e[3]}</span></td><td>{e[4]}</td></tr>" for e in events])
    whitelisted_li = "".join([f"<li>{ip} ({get_country_by_ip(ip)}) <form action='/action/remove' method='post' style='display:inline;'><input type='hidden' name='ip' value='{ip}'><button type='submit' style='padding:2px 6px; background:#95a5a6; font-size:11px;'>Удалить</button></form></li>" for ip in whitelisted_ips]) or "<li>Список пуст</li>"
    blocked_li = "".join([f"<li><b>{ip}</b> ({get_country_by_ip(ip)}) <form action='/action/remove' method='post' style='display:inline;'><input type='hidden' name='ip' value='{ip}'><button type='submit' style='padding:2px 6px; background:#e74c3c; font-size:11px;'>Разблокировать</button></form></li>" for ip in blocked_ips]) or "<li>Нет активных блокировок</li>"

    html_content = f"""
    <html>
    <head>
        <title>Kernel IPS Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f4f6f9; }}
            
            /* Стили навигационной панели */
            .navbar {{ background: #2c3e50; padding: 12px 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }}
            .navbar-brand {{ color: white; font-size: 18px; font-weight: bold; text-decoration: none; }}
            .services-links {{ display: flex; gap: 15px; }}
            .service-btn {{ color: #ecf0f1; text-decoration: none; padding: 6px 14px; border-radius: 4px; background: #34495e; font-size: 13px; font-weight: 500; transition: 0.2s; border: 1px solid #4f5d73; }}
            .service-btn:hover {{ background: #3498db; color: white; border-color: #3498db; }}
            .service-btn.alert-btn {{ border-color: #e74c3c; }}
            .service-btn.alert-btn:hover {{ background: #e74c3c; }}
            
            /* Основной контейнер */
            .main-content {{ padding: 30px; }}
            .container {{ display: flex; gap: 20px; }}
            .box {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); flex: 1; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background: #35495e; color: white; }}
            input[type=text] {{ padding: 8px; width: 200px; border: 1px solid #ccc; border-radius: 4px; }}
            button {{ padding: 8px 15px; background: #2ecc71; color: white; border: none; border-radius: 4px; cursor: pointer; }}
            button.block {{ background: #e74c3c; }}
            button.clear {{ background: #7f8c8d; width: 100%; margin-top: 15px; }}
            .badge {{ background: #e2e8f0; padding: 6px 12px; border-radius: 4px; color: #2c3e50; font-size: 13px; font-weight: bold; }}
        </style>
    </head>
    <body>
        <!-- НАВИГАЦИОННАЯ ПАНЕЛЬ С ВАШИМИ СЕРВИСАМИ -->
        <div class="navbar">
            <a class="navbar-brand" href="/">🛡️ XDP / eBPF Kernel IPS</a>
            <div class="services-links">
                <a href="http://45.9.15.253:8001/" target="_blank" class="service-btn alert-btn">⚔️ Контратака</a>
                <a href="http://45.9.15.253:8002/" target="_blank" class="service-btn">🎛️ Управление шлюзом</a>
                <a href="http://45.9.15.253:8005/" target="_blank" class="service-btn">🖥️ Мониторинг системы</a>
                <a href="/docs" target="_blank" class="service-btn" style="background:#27ae60; border-color:#27ae60;">📑 Swagger API</a>
            </div>
            <div class="badge">👤 {username}</div>
        </div>

        <div class="main-content">
            <p>Активная защита на интерфейсе: <b>{INTERFACE}</b></p>
            <div class="container">
                <div class="box">
                    <h2>Управление правилами</h2>
                    <form action="/action/whitelist" method="post"><input type="text" name="ip" placeholder="192.168.1.100" required><button type="submit">В Белый список</button></form><br>
                    <form action="/action/blacklist" method="post"><input type="text" name="ip" placeholder="10.0.0.5" required><button type="submit" class="block">Блокировать IP</button></form>
                    <form action="/action/clear-all" method="post" onsubmit="return confirm('Очистить ВСЕ данные?');"><button type="submit" class="clear">🧹 Полная очистка данных</button></form>
                    <h3>Текущие белые списки в ядре:</h3><ul>{whitelisted_li}</ul>
                    <h3>Активные блокировки в ядре:</h3><ul>{blocked_li}</ul>
                </div>
                <div class="box" style="flex: 2;">
                    <h2>Журнал событий ИИ и Автоблокировок (PostgreSQL)</h2>
                    <form action="/" method="get" style="margin-bottom:15px; display:flex; gap:10px;"><input type="text" name="search_ip" placeholder="Поиск по IP..." value="{search_ip or ''}"><button type="submit" style="background:#3498db;">Найти</button>{f"<a href='/' style='padding:8px 12px; background:#bdc3c7; color:black; text-decoration:none; border-radius:4px;'>Сбросить</a>" if search_ip else ""}</form>
                    <table><tr><th>Время</th><th>IP Источник (GeoIP)</th><th>Порт</th><th>Действие</th><th>Причина</th></tr>{table_rows or "<tr><td colspan='5'>Событий не найдено</td></tr>"}</table>
                </div>
            </div>
        </div>
    </body>
    </html>"""
    local_cursor.close(); local_conn.close()
    return html_content

@app.post("/action/whitelist")
def web_whitelist(ip: str = Form(...), username: str = Depends(authenticate_user)):
    try:
        key = ctypes.c_uint32(ip_to_u32(ip))
        bpf_ctx["whitelist_map"][key] = ctypes.c_uint8(1)
        try: del bpf_ctx["blacklist_map"][key]
        except KeyError: pass
        local_conn = psycopg2.connect(db_conf); local_cursor = local_conn.cursor()
        local_cursor.execute("INSERT INTO managed_lists (src_ip, list_type, updated_at) VALUES (%s, 'WHITE', CURRENT_TIMESTAMP) ON CONFLICT (src_ip) DO UPDATE SET list_type = 'WHITE', updated_at = CURRENT_TIMESTAMP;", (ip,))
        local_conn.commit(); local_cursor.close(); local_conn.close()
    except Exception as e: print(f"[-] Ошибка белого списка: {e}")
    return HTMLResponse("<script>window.location.href='/';</script>")

@app.post("/action/blacklist")
def web_blacklist(ip: str = Form(...), username: str = Depends(authenticate_user)):
    try: trigger_auto_block(ip, 0, "Manual Administrator Block")
    except Exception as e: print(f"[-] Ошибка ручной блокировки: {e}")
    return HTMLResponse("<script>window.location.href='/';</script>")

@app.post("/action/remove")
def web_remove_ip(ip: str = Form(...), username: str = Depends(authenticate_user)):
    try:
        key = ctypes.c_uint32(ip_to_u32(ip))
        for m in ["blacklist_map", "whitelist_map"]:
            try: del bpf_ctx[m][key]
            except KeyError: pass
        local_conn = psycopg2.connect(db_conf); local_cursor = local_conn.cursor()
        local_cursor.execute("DELETE FROM managed_lists WHERE src_ip = %s;", (ip,))
        local_cursor.execute("INSERT INTO security_events (src_ip, dport, action, reason) VALUES (%s, 0, 'UNBANNED', 'Manual Removal')", (ip,))
        local_conn.commit(); local_cursor.close(); local_conn.close()
    except Exception as e: print(f"[-] Ошибка удаления IP: {e}")
    return HTMLResponse("<script>window.location.href='/';</script>")

@app.post("/action/clear-all")
def web_clear_all_data(username: str = Depends(authenticate_user)):
    try:
        for m in ["blacklist_map", "whitelist_map"]:
            for k in list(bpf_ctx[m].keys()):
                try: del bpf_ctx[m][k]
                except KeyError: pass
        local_conn = psycopg2.connect(db_conf); local_cursor = local_conn.cursor()
        local_cursor.execute("TRUNCATE TABLE managed_lists CASCADE;")
        local_cursor.execute("TRUNCATE TABLE security_events CASCADE;")
        local_cursor.execute("INSERT INTO security_events (src_ip, dport, action, reason) VALUES ('0.0.0.0', 0, 'CLEARED', 'Global DB & Kernel maps reset by Admin')")
        local_conn.commit(); local_cursor.close(); local_conn.close()
    except Exception as e: print(f"[-] Ошибка глобального сброса: {e}")
    return HTMLResponse("<script>window.location.href='/';</script>")
