import socket
import struct
import threading
import queue
import ctypes  # Добавлено для строгой типизации данных ядра
import numpy as np
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
from bcc import BPF
import psycopg2
from sklearn.ensemble import IsolationForest

app = FastAPI(title="XDP Kernel IDS/IPS")

# Загрузка конфигурации сетевого интерфейса
with open("ids.conf", "r") as f:
    config_content = f.read()
    INTERFACE = config_content.split("=")[1].replace('"', '').strip()

# Инициализация базы данных PostgreSQL
db_conf = "dbname=ids_db user=postgres password=ids_pass host=localhost"
conn = psycopg2.connect(db_conf)
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id SERIAL PRIMARY KEY,
        src_ip TEXT,
        dport INT,
        action TEXT,
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")
conn.commit()

# Компиляция и загрузка Си-кода фильтрации прямо в сетевой драйвер (XDP)
bpf_ctx = BPF(src_file="xdp_filter.c")
bpf_fn = bpf_ctx.load_func("xdp_fw_router", BPF.XDP)
bpf_ctx.attach_xdp(INTERFACE, bpf_fn, 0)

# Потокобезопасная очередь для передачи сетевых событий в ИИ без блокировки ядра
ai_queue = queue.Queue(maxsize=10000)

def u32_to_ip(ip_num):
    return socket.inet_ntoa(struct.pack("<I", ip_num))

def ip_to_u32(ip_str):
    # Извлекаем число u32 из кортежа struct.unpack
    return struct.unpack("<I", socket.inet_aton(ip_str))[0]

def trigger_auto_block(ip_str, port, reason):
    """ Внесение вредоносного IP в хэш-карту ядра для мгновенного XDP_DROP """
    try:
        ip_num = ip_to_u32(ip_str)
        # Строгая типизация ключа и значения через ctypes для корректной записи в память ядра
        key = ctypes.c_uint32(ip_num)
        val = ctypes.c_uint8(1)
        bpf_ctx["blacklist_map"][key] = val
        
        # Логирование инцидента безопасности в базу данных
        local_conn = psycopg2.connect(db_conf)
        local_cursor = local_conn.cursor()
        local_cursor.execute(
            "INSERT INTO security_events (src_ip, dport, action, reason) VALUES (%s, %s, 'BLOCKED', %s)",
            (ip_str, port, reason)
        )
        local_conn.commit()
        local_cursor.close()
        local_conn.close()
        print(f"[SYSTEM-IDS] IP {ip_str} успешно заблокирован в ядре. Причина: {reason}")
    except Exception as e:
        print(f"[-] Ошибка выполнения автоблокировки: {e}")

def ai_worker_thread():
    """ Изолированный поток ИИ-движка (Isolation Forest) """
    ai_model = IsolationForest(contamination=0.02, random_state=42)
    traffic_buffer = []
    
    while True:
        try:
            ip_str, dport, sport = ai_queue.get()
            traffic_buffer.append([dport, sport])
            
            if len(traffic_buffer) >= 50:
                data_matrix = np.array(traffic_buffer)
                ai_model.fit(data_matrix)
                predictions = ai_model.predict(data_matrix)
                
                if predictions[-1] == -1:
                    trigger_auto_block(ip_str, dport, "AI Anomaly: Async Port Scan / Flood Detected")
                
                traffic_buffer = traffic_buffer[-20:]
                
            ai_queue.task_done()
        except Exception as e:
            print(f"[-] Ошибка в потоке ИИ: {e}")

def packet_callback(cpu, data, size):
    """ Скоростной коллбэк для перехвата данных из Perf Buffer ядра """
    try:
        event = bpf_ctx["events"].event(data)
        ip_str = u32_to_ip(event.src_ip)
        
        if not ai_queue.full():
            ai_queue.put_nowait((ip_str, event.dport, event.sport))
    except Exception:
        pass

def run_ebpf_polling():
    bpf_ctx["events"].open_perf_buffer(packet_callback, page_cnt=256)
    while True:
        try:
            bpf_ctx.perf_buffer_poll()
        except Exception:
            break

@app.on_event("startup")
def start_background_tasks():
    threading.Thread(target=ai_worker_thread, daemon=True).start()
    threading.Thread(target=run_ebpf_polling, daemon=True).start()

# ==============================================================================
# ВЕБ-ИНТЕРФЕЙС (DASHBOARD)
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
def dashboard():
    local_conn = psycopg2.connect(db_conf)
    local_cursor = local_conn.cursor()
    local_cursor.execute("SELECT created_at, src_ip, dport, action, reason FROM security_events ORDER BY created_at DESC LIMIT 30;")
    events = local_cursor.fetchall()
    
    # ИСПРАВЛЕНО: Чтение сырого числового значения .value из ключа карты ядра
    blocked_ips = [u32_to_ip(k.value) for k, v in bpf_ctx["blacklist_map"].items()]
    whitelisted_ips = [u32_to_ip(k.value) for k, v in bpf_ctx["whitelist_map"].items()]
    
    # Разбор индексов кортежа (e[0]=время, e[1]=IP, e[2]=порт...)
    table_rows = "".join([f"<tr><td>{e[0]}</td><td><b>{e[1]}</b></td><td>{e[2]}</td><td><span style='color:red'>{e[3]}</span></td><td>{e[4]}</td></tr>" for e in events])
    
    html_content = f"""
    <html>
    <head>
        <title>Kernel-Level IPS Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 30px; background-color: #f4f6f9; }}
            h1, h2 {{ color: #333; }}
            .container {{ display: flex; gap: 20px; }}
            .box {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); flex: 1; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #35495e; color: white; }}
            input[type=text] {{ padding: 8px; width: 200px; border: 1px solid #ccc; border-radius: 4px; }}
            button {{ padding: 8px 15px; background: #2ecc71; color: white; border: none; border-radius: 4px; cursor: pointer; }}
            button.block {{ background: #e74c3c; }}
        </style>
    </head>
    <body>
        <h1>🛡️ Монитор сетевой безопасности ядра (XDP / eBPF)</h1>
        <p>Активная защита на интерфейсе: <b>{INTERFACE}</b></p>
        
        <div class="container">
            <div class="box">
                <h2>Управление правилами</h2>
                <form action="/action/whitelist" method="post">
                    <input type="text" name="ip" placeholder="192.168.1.100" required>
                    <button type="submit">Добавить в Белый список</button>
                </form>
                <br>
                <form action="/action/blacklist" method="post">
                    <input type="text" name="ip" placeholder="10.0.0.5" required>
                    <button type="submit" class="block">Заблокировать IP вручную</button>
                </form>
                
                <h3>Текущие белые списки в ядре:</h3>
                <ul>{"".join([f"<li>{ip}</li>" for ip in whitelisted_ips]) or "<li>Список пуст</li>"}</ul>
                <h3>Активные блокировки в ядре:</h3>
                <ul>{"".join([f"<li>{ip}</li>" for ip in blocked_ips]) or "<li>Нет active-блокировок</li>"}</ul>
            </div>
            
            <div class="box" style="flex: 2;">
                <h2>Журнал событий ИИ и Автоблокировок (PostgreSQL)</h2>
                <table>
                    <tr><th>Время</th><th>IP Источник</th><th>Порт назначения</th><th>Действие</th><th>Причина</th></tr>
                    {table_rows or "<tr><td colspan='5'>Событий безопасности пока не зафиксировано</td></tr>"}
                </table>
            </div>
        </div>
    </body>
    </html>
    """
    local_cursor.close()
    local_conn.close()
    return html_content

@app.post("/action/whitelist")
def web_whitelist(ip: str = Form(...)):
    try:
        ip_num = ip_to_u32(ip)
        # ИСПРАВЛЕНО: Строгое приведение типов ctypes для записи ключа в whitelist_map ядра
        key = ctypes.c_uint32(ip_num)
        val = ctypes.c_uint8(1)
        bpf_ctx["whitelist_map"][key] = val
        
        # Безопасное удаление из черного списка ядра оператором del
        try:
            del bpf_ctx["blacklist_map"][key]
        except KeyError:
            pass
            
    except Exception as e:
        print(f"[-] Ошибка при обработке белого списка: {e}")
    return HTMLResponse("<script>window.location.href='/';</script>")

@app.post("/action/blacklist")
def web_blacklist(ip: str = Form(...)):
    trigger_auto_block(ip, 0, "Manual Administrator Block")
    return HTMLResponse("<script>window.location.href='/';</script>")
