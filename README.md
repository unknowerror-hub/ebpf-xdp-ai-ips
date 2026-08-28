# 🛡️ XDP/eBPF AI-Driven IPS & Gateway Infrastructure Engine

Комплексная экосистема сетевой безопасности, маршрутизации и мониторинга инфраструктуры на уровне ядра Linux с использованием **eBPF/XDP**, ИИ-аналитикой аномалий на базе **Isolation Forest** и модулем активного контр-наступления (**RAW Sockets**).

---

## 🛠️ Архитектура распределенных компонентов

Система состоит из 4 независимых сервисов, обеспечивающих отказоустойчивость:
1. **Основной щит (Shield Core - Port 8000)**: FastAPI бэкенд, управляющий картами eBPF, собирающий логи пакетов в PostgreSQL и обучающий модель ИИ для детекции сканирования портов.
2. **Модуль возмездия (Retaliation Engine - Port 8001)**: Асинхронный оркестратор, автоматически выжигающий каналы атакующих серверов сырыми пакетами (TCP SYN/UDP Flood) с системой проверки доступности цели (**Target Health Check**).
3. **Управление Шлюзом (Gateway Router - Port 8002)**: Модуль маршрутизации, NAT-маскарадинга, управления DHCP-пулами/DNS (`dnsmasq`), OpenVPN-сервером и автоматическим переключением каналов Интернета (**Internet Failover**).
4. **Инфраструктурный Мониторинг (System Monitor - Port 8005)**: Асинхронный демон сбора метрик железа (CPU, RAM, Disk, I/O сетевых карт) и состояния подсистем ядра в реальном времени.

---

## 📁 Обновленная структура репозитория

```text
├── config/
│   └── ids.conf                # Конфигурация интерфейса безопасности
├── core/
│   └── src/
│       └── xdp_filter.c        # Программа ядра eBPF (Си)
├── src/
│   ├── ai/
│   │   └── counter_core.py     # Модуль контр-атаки (Порт 8001)
│   └── web/
│       ├── main.py             # Главный дашборд IPS (Порт 8000)
│       ├── gateway.py     # Панель маршрутизации шлюза (Порт 8002)
│       └── monitor_core.py     # Демон системного мониторинга (Порт 8005)
├── static/
│   ├── css/
│   │   └── style.css         # Стили интерфейса мониторинга
│   └── js/
│       └── app.js          # Клиентская логика опроса API метрик
├── dashboard.html              # Шаблон страницы мониторинга
├── .gitignore                  # Исключение кэша, venv и логов
├── requirements.txt            # Зависимости Python
└── README.md                   # Данная инструкция
```

---

## 🚀 Инструкция по установке и развертыванию

### 1. Установка системных зависимостей
```bash
sudo apt update
sudo apt install -y linux-headers-\$(uname -r) bpfcc-tools libbpfcc-dev clang llvm postgresql postgresql-contrib git python3-pip python3-venv dnsmasq openvpn iptables
```

### 2. Настройка СУБД PostgreSQL
```bash
sudo -u postgres psql -c "CREATE DATABASE ids_db;"
sudo -u postgres psql -c "CREATE USER postgres WITH PASSWORD 'ids_pass';"
sudo -u postgres psql -d ids_db -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;"
```

### 3. Клонирование и подготовка окружения
```bash
git clone https://github.com
cd ebpf-xdp-ai-ips

# Создание venv со сквозным доступом к глобальной библиотеке BCC
python3 -m venv venv --system-site-packages
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🚦 Сетевая матрица и запуск

Все компоненты требуют привилегий `root` для взаимодействия со структурами ядра Linux и сырыми сокетами.

| Компонент | Скрипт запуска | Внутренний порт | Назначение |
| :--- | :--- | :--- | :--- |
| **IPS Shield** | `src/web/main.py` | `:8000` | Фильтрация eBPF/XDP и ИИ |
| **Counter-Attack** | `src/ai/counter_core.py` | `:8001` | Подавление RAW Sockets |
| **Gateway Router** | `src/web/gateway_core.py` | `:8002` | Настройка NAT/DHCP/VPN/Failover |
| **System Monitor** | `src/web/monitor_core.py` | `:8005` | Real-time метрики ядра и ОС |

### Команды запуска (в разных окнах терминала или tmux/screen):
```bash
sudo ./venv/bin/python3 src/web/main.py
sudo ./venv/bin/python3 src/ai/counter_core.py
sudo ./venv/bin/python3 src/web/gateway_core.py
sudo ./venv/bin/python3 src/web/monitor_core.py
```

*Данные авторизации во все панели:* Логин: `admin` | Пароль: `kernel_secure_2026`
