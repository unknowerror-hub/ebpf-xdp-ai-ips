# 🛡️ XDP/eBPF AI-Driven IPS & Counter-Attack Engine

Комплексная система обнаружения и предотвращения вторжений (IDS/IPS) на уровне ядра Linux с использованием **eBPF/XDP**, ИИ-аналитикой аномалий трафика на базе **Isolation Forest** и модулем активного наступательного противодействия (**RAW Sockets TCP/UDP Flood**).

---

## 🛠️ Архитектура системы

Проект разделен на изолированные слои для обеспечения максимальной производительности:
1. **Ядро защиты (eBPF/XDP)**: Слой Си-кода (`xdp_filter.c`), работающий непосредственно в драйвере сетевой карты. Фильтрует или дропает пакеты до прохождения сетевого стека ОС, экономя 99% CPU при DDoS.
2. **Основной щит (Shield Core - Port 8000)**: FastAPI бэкенд, управляющий картами eBPF, собирающий логи в PostgreSQL и обучающий локальную модель ИИ для детекции сканирования портов.
3. **Модуль возмездия (Retaliation Engine - Port 8001)**: Асинхронный оркестратор, автоматически выжигающий каналы атакующих серверов сырыми пакетами с системой **Target Health Check** (автовыключение при падении цели).

---

## 📁 Структура репозитория

```text
├── config/
│   └── ids.conf                # Настройки сетевых интерфейсов
├── core/
│   └── src/
│       └── xdp_filter.c        # Программа ядра eBPF (Си)
├── src/
│   ├── ai/
│   │   └── counter_core.py     # Модуль контр-атаки и RAW-сокетов
│   └── web/
│       └── main.py             # Главный дашборд IPS и логика eBPF
├── .gitignore                  # Исключение venv, логов и кэша
├── requirements.txt            # Зависимости Python библиотеки
└── README.md                   # Данное руководство
```

---

## 🚀 Инструкция по установке и развертыванию

### 1. Системные требования
* **ОС**: Ubuntu 22.04 LTS / 24.04 LTS (Ядро Linux 5.15+)
* **Пакеты**: Компилятор Clang, LLVM и заголовочные файлы ядра Linux, СУБД PostgreSQL.

### 2. Установка системных зависимостей
```bash
sudo apt update
sudo apt install -y linux-headers-$(uname -r) bpfcc-tools libbpfcc-dev clang llvm postgresql postgresql-contrib git python3-pip python3-venv
```

### 3. Настройка Базы Данных PostgreSQL
```bash
sudo -u postgres psql -c "CREATE DATABASE ids_db;"
sudo -u postgres psql -c "CREATE USER postgres WITH PASSWORD 'ids_pass';"
sudo -u postgres psql -d ids_db -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;"
```

### 4. Клонирование и подготовка окружения
```bash
# Клонируйте этот приватный репозиторий
git clone https://github.com
cd ebpf-xdp-ai-ips

# Создание виртуального окружения со сквозным доступом к BCC (обязательно!)
python3 -m venv venv --system-site-packages
source venv/bin/activate
pip install -r requirements.txt
```

### 5. Конфигурация интерфейса
Отредактируйте файл `config/ids.conf`, указав вашу сетевую карту (например, `eth0` или `ens3`):
```text
INTERFACE="eth0"
```

---

## 🚦 Запуск компонентов

Система запускается строго от имени суперпользователя `root`, так как eBPF требует привилегий загрузки в пространство ядра.

**Запуск основного Щита и Панели Мониторинга (Порт 8000):**
```bash
sudo ./venv/bin/python3 src/web/main.py
```

**Запуск Наступательного Модуля Возмездия (Порт 8001):**
```bash
sudo ./venv/bin/python3 src/ai/counter_core.py
```

*Доступ к веб-панелям:* `http://SERVER_IP:8000` и `http://SERVER_IP:8001`
*Данные для входа:* Логин: `admin` | Пароль: `kernel_secure_2026`
