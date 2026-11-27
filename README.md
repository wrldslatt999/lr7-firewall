# ЛР №7. Розробка програмного брандмауера

**Виконав:** Чучула Євгеній Андрійович  
**Дисципліна:** Прикладні аспекти програмування  
**Технологія:** Python 3.11+, стандартна бібліотека (`socketserver`, `socket`, `http.server`, `ipaddress`, `threading`)  
**Середовище демонстрації:** Kali Linux. Права `sudo` не потрібні.

## Призначення

Навчальний **TCP/UDP proxy firewall** за структурою `додаток_лр_7.rar` викладача. Фільтрує з'єднання TCP і датаграми UDP, що проходять **через налаштовані проксі-порти**, на підставі адреси, порту, протоколу, напряму й пріоритету. Правила оновлюються через локальний захищений токеном Admin API **без зупинення служби**, зберігаються у `config.json` і залишаються після перезапуску.

**Межа застосування:** це НЕ системний packet firewall. Він не перехоплює довільний мережевий трафік комп'ютера, не змінює `nftables` та не перевіряє кожен TCP-пакет окремо: TCP-фільтрація виконується під час встановлення нового з'єднання, UDP — для кожної датаграми. Для повноцінного захисту ОС слід інтегрувати механізми ядра (`nftables`/Netfilter). Це відповідає проксі-архітектурі з додатка викладача.

## Швидка перевірка без встановлення бібліотек

Після завантаження та розпакування архіву в Kali:

```bash
cd ~/Downloads/LR7_Firewall_Chuchula
python3 -m unittest discover -s tests -v
python3 -m tools.run_demo --out docs/kali-demo.json
```

Друга команда **реально запускає** локальні TCP/UDP-сервери, проксі, запити клієнта й Admin API на тимчасових портах, перевіряє зміну правил і записує протокол запуску. У файлі `docs/kali-demo.json` будуть дані саме твоєї Kali. Паролі й ключі не зберігаються в цьому звіті.

## Покрокова ручна демонстрація (3 термінали Kali)

Спочатку **один раз** ініціалізуй локальні файли конфігурації й секрет API:

```bash
python3 tools/setup_lab.py
```

**Термінал №1 — локальний TCP/UDP echo-сервер** (не закривай):

```bash
python3 -m tools.echo_backend
```

**Термінал №2 — проксі-брандмауер** (не закривай):

```bash
python3 firewall.py --config config.json
```

**Термінал №3 — клієнт і керування правилами:**

```bash
# TCP: дозволено за замовчуванням
python3 -m tools.demo_client --proto TCP --msg "TCP BEFORE"

# UDP: також дозволено
python3 -m tools.demo_client --proto UDP --msg "UDP BEFORE"

# Блокувати ВХІДНІ TCP-з'єднання до цільового порту 19080
python3 fwctl.py add --action deny --direction in --proto TCP --dst-port 19080

# Перевірка: response bytes=0, blocked or upstream unavailable
python3 -m tools.demo_client --proto TCP --msg "TCP BLOCKED"

# Список правил: знайди id (на чистій конфігурації буде 1)
python3 fwctl.py list

# Вимкнення без рестарту (підстав фактичний id, наприклад 1)
python3 fwctl.py disable 1
python3 -m tools.demo_client --proto TCP --msg "TCP AGAIN"

# Повторне увімкнення правила
python3 fwctl.py enable 1
python3 fwctl.py conflicts

# Оцінка існуючого правила без створення трафіку — лише симуляція
python3 fwctl.py evaluate --direction in --proto TCP --src-ip 127.0.0.1 --dst-ip 127.0.0.1 --src-port 50000 --dst-port 19080

# Аналіз журналу: кількість відмов, джерела, причини, часові мітки
python3 analyze_logs.py logs/events.jsonl --action deny --out docs/kali-log-analysis.json
```

**Важливо:** у правилах `dst_port` означає порт **кінцевого сервера (19080)**, а проксі слухає окремий порт `18080`. Для UDP кінцевий порт `19053`, проксі слухає `15353`.

## Топологія та локальні адреси

```text
TCP: клієнт 127.0.0.1:ephemeral → firewall 127.0.0.1:18080 → echo-server 127.0.0.1:19080
UDP: клієнт 127.0.0.1:ephemeral → firewall 127.0.0.1:15353 → echo-server 127.0.0.1:19053
                                      │
                                      └─ Admin API 127.0.0.1:18081 (X-Admin-Token)
```

Простір IP — loopback однієї ОС, тому це **різні процеси/сокети, а не різні фізичні вузли**. Для цієї ЛР викладач не вимагає двох окремих віртуальних машин.

## Формат правила

```json
{
  "id": 1,
  "action": "deny",
  "direction": "in",
  "src_ip_cidr": "127.0.0.1/32",
  "dst_ip_cidr": "127.0.0.1/32",
  "src_port": 0,
  "dst_port": 19080,
  "proto": "TCP",
  "priority": 100,
  "enabled": true
}
```

`src_port=0` та `dst_port=0` означають будь-який порт. Підтримуються лише IPv4, TCP, UDP. `id` призначається автоматично. Нижче число `priority` означає вищий пріоритет. При однаковому пріоритеті **deny перед allow**, потім менший `id`. Діє перше правило, яке збіглося; базова політика у шаблоні — `allow` (змінюється в `config.json` до запуску).

Дублікат ідентичного правила відхиляється (`HTTP 409`), перетин CIDR і портів із протилежною дією повідомляється у `warnings` та `/conflicts`, але правило додається. Цим дозволено продемонструвати керовану зміну пріоритетів. Див. [аналіз конфліктів](docs/rules-and-conflicts.md).

## Журнал і захист Admin API

Кожне відхилене TCP-з'єднання або UDP-датаграма записується в локальний файл `logs/events.jsonl`: UTC-час, IP джерела й призначення, порти, напрям, протокол, ID правила, причина (`matched_rule_ID`). Записи доступні для фільтрування за протоколом, CIDR, напрямом, дією та періодом часу.

Admin API на `127.0.0.1:18081` вимагає випадковий токен із `.firewall/admin.token` (створює `setup_lab.py` із правами 0600). Програма `fwctl.py` читає його сама й не друкує. Запити без токена отримують `401`. Для віддаленого адміністрування потрібні додаткові засоби захисту — не відкривай цей HTTP API в зовнішню мережу.

**Локальні та секретні файли** (`config.json`, `.firewall/`, `logs/`) не додаються до Git. Для підсумкового звіту в GitHub команди записують безпечні дані у `docs/kali-demo.json` і `docs/kali-log-analysis.json`.

## Структура

| Файл | Призначення |
|---|---|
| `firewall.py` | Основна служба й Admin REST API |
| `proxy.py` | Фактичне приймання TCP-з'єднань і UDP-датаграм |
| `rule_engine.py` | Правила, CIDR/порти, пріоритет, конфлікти, збереження |
| `eventlog.py`, `analyze_logs.py` | JSONL-журнали та пошук |
| `fwctl.py` | Керування правилами без перезапуску |
| `tools/setup_lab.py` | Безпечна локальна ініціалізація |
| `tools/echo_backend.py`, `tools/demo_client.py` | Реальний локальний обмін |
| `tools/run_demo.py` | Автоматична наскрізна демонстрація з підтвердженням результату |
| `tests/` | 43 модульні й інтеграційні тести |
| `docs/LR7_report.md` | Звіт за 3 завданнями |
| `.github/workflows/tests.yml` | GitHub Actions (Python 3.11–3.13) |

## Результати тестування

Локальне Linux-середовище підготовки проєкту: `python -m unittest discover -s tests -q` → **43 тести, OK**. Окремий `tools.run_demo` перевірив дозвіл/заборону TCP і UDP, віддалене перемикання правила через Admin API, конфлікти й журнали. Результат цієї перевірки не видається за запуск на Kali: див. [протокол](docs/verification.md). Для отримання підтвердження саме у Kali виконай вказані вище команди.

## Джерела

1. Додаток викладача `додаток_лр_7.rar`: `firewall.py`, `analyze_logs.py`, `config.json`, `README.md` — вихідний каркас.
2. [Python — socketserver](https://docs.python.org/3/library/socketserver.html).
3. [Python — HTTP server](https://docs.python.org/3/library/http.server.html).
4. [nftables wiki — Netfilter hooks](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks) — розмежування системної фільтрації та навчального проксі.
