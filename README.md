# Reverse SOCKS5, UDP, HTTP & MTProto Proxy Cluster (Go High-Speed)

[![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version Available](https://img.shields.io/badge/Python%20Version-AsyncIO-blue.svg)](https://github.com/zenkdom/reverse-socks-python)
[![Telegram Fake-TLS 1.3](https://img.shields.io/badge/Telegram-MTProto%20Fake--TLS-blue.svg)](https://telegram.org)

> [!NOTE]
> 🔄 **100% Кроссплатформенная совместимость протокола:**  
> Go-версия и **[Python-версия](https://github.com/zenkdom/reverse-socks-python)** используют полностью идентичный бинарный протокол. Исполняющий агент на Go (`socks-reverse`) может подключаться к Control-серверу на Python, а агент на Python — к Control-серверу на Go.

Высокопроизводительная реализация обратного прокси-кластера на **Go**:
- **Универсальный Multi-Protocol прокси** (порт `1080`):
  - **SOCKS5 с поддержкой TCP и UDP**: команды `CONNECT` (0x01), `BIND` (0x02), и `UDP ASSOCIATE` (0x03) по RFC 1928 / RFC 1929. Полная поддержка звонков Telegram, голосовых чатов, WebRTC, DNS, онлайн-игр и QUIC/HTTP3.
  - **SOCKS4 и SOCKS4a**: поддержка классических клиентов и удаленного резолва доменов.
  - **HTTP & HTTPS (CONNECT) Proxy**: поддержка туннелирования HTTPS-трафика и прямого HTTP-проксирования с Proxy-Authorization Basic.
  - Автоматическое определение протокола на лету на едином порту 1080.
- **MTProto Fake-TLS прокси** (порт `8443`) для Telegram в обход блокировок ТСПУ / РКН:
  - Режимы Fake-TLS 1.3 (`ee...`) и Obfuscated2 (`Hex32`).
  - Привязка промо-каналов (TAG) из `@MTProxybot`.
  - Защита от активных зондов ТСПУ: перенаправление зондов на google.com с возвратом валидного сертификата Google.
- **Встроенная веб-админка** (порт `9001`) для управления пользователями и мониторинга нод.
- **Пул исполняющих серверов (`socks-reverse`)** для вывода трафика в интернет с независимой ротацией по пользователям и мгновенным failover (2 секунды).
- **Multi-Tor Cluster (`reverse-multi-tor`) на 10 нод**: запуск пула изолированных нод с уникальными внешними IP через Tor IsolateSOCKSAuth.
  > ⚠️ *Важно о скорости сети Tor:* маршрутизация через Tor дает высокий пинг (300–800мс) и невысокую скорость. Для высоких нагрузок, звонков и комфортного сёрфинга **рекомендуется использовать собственные VPS/серверы** с агентом `socks-reverse`.

---

## ⚡ Преимущества реализации на Go («работает максимально быстро»)

1. **Аппаратное ускорение шифрования AES-NI**:
   - В Python (`cryptography`) вызовы C-библиотек через CFFI создают накладные расходы при каждом пакете.
   - В Go стандартный пакет `crypto/aes` напрямую использует инструкции процессора **AES-NI** на уровне ассемблера, обеспечивая пропускную способность шифрования в несколько гигабайт в секунду при минимальной нагрузке на процессор.
2. **Нулевые паузы GC и буферный пул (`sync.Pool`)**:
   - Переиспользование 32-КБ сетевых буферов исключает постоянные аллокации памяти в куче, предотвращая задержки Garbage Collector под высокой нагрузкой.
3. **Нативный сетевой поллер (IOCP на Windows / epoll на Linux)**:
   - Легковесные горутины требуют всего несколько килобайт памяти на соединение (в десятки раз меньше Python `asyncio.Task`), что позволяет удерживать сотни тысяч одновременных TCP/UDP потоков.
4. **TCP NoDelay и KeepAlive**:
   - По умолчанию отключен алгоритм Нейгла (`SetNoDelay(true)`) для мгновенной доставки интерактивных пакетов и минимизации пинга.
5. **Автономные бинарные файлы**:
   - Никаких внешних зависимостей, pip или интерпретаторов — статически скомпилированные бинарники запускаются одной командой на Windows и Linux.

---

## 🏗 Архитектура

```
                             +---------------------------------------+
                             |           ВЕБ-АДМИНИСТРАТОР           |
                             |      http://IP_CONTROL:9001           |
                             |       Логин: admin / changeme123          |
                             +-------------------+-------------------+
                                                 |
                                                 | 1-клик подключение в Telegram /
                                                 | Управление пользователями SOCKS5
                                                 v
+---------------------------------------+   +---------------------------------------+
|             КЛИЕНТЫ                   |   |             socks-control             |
|   (Браузер, curl, v2rayNG и т.д.)     |   |          (Написан на Go)              |
+-------------------+-------------------+   |                                       |
                    | SOCKS5 с логином      |   * Порт 1080: SOCKS5 (СТРОГО AUTH)   |
                    +---------------------->|   * Порт 8443: MTProto Fake-TLS (TG)  |
                                            |   * Порт 9000: Порт для reverse-нод   |
+---------------------------------------+   |   * Порт 9001: Веб-админка            |
|            TELEGRAM КЛИЕНТ            |   |   * Балансировщик: ROTATION (ротация) |
|       (Windows, Android, iOS)         |   +-------------------+-------------------+
+-------------------+-------------------+                       ^
                    | MTProto Fake-TLS (8443)                           |
                    | (маскировка под google.com)                       |
                    +---------------------------------------------------+
                                                                        |
                                               Исходящие туннели        |
                                +---------------------------------------+---------------------------------------+
                                |                                                                               |
                                | Порт 9000                                                             | Порт 9000
                                v                                                                               v
                   +-------------------------+                                                     +-------------------------+
                   |      socks-reverse      |                                                     |      socks-reverse      |
                   |    (Исполняющий #1)     |                                                     |    (Исполняющий #2)     |
                   |     reverse-node-1      |                                                     |     reverse-node-2      |
                   +------------+------------+                                                     +------------+------------+
                                |                                                                               |
                                | Выход в интернет                                                              | Выход в интернет
                                v                                                                               v
                   +-------------------------+                                                     +-------------------------+
                   |    Интернет / Сайты     |                                                     |    Telegram DC (443)    |
                   |     (IP первой ноды)    |                                                     |    (IP второй ноды)     |
                   +-------------------------+                                                     +-------------------------+
```

---

## 📁 Структура папки `go/`

```text
go/
├── cmd/
│   ├── socks-control/       # Главный сервер (SOCKS5 + MTProto + Control Bridge + Web UI)
│   ├── socks-reverse/       # Исполняющий агент (выход в интернет)
│   └── reverse-multi-tor/   # Оркестратор Tor-кластера с гарантией уникальных IP
├── pkg/
│   ├── protocol/            # Бинарный протокол RSX5, Fake-TLS 1.3, SOCKS5 UDP
│   ├── control/             # Управление reverse-агентами, ротация, failover
│   ├── proxy/               # SOCKS5 (TCP, UDP, BIND), SOCKS4/4a, HTTP/HTTPS
│   ├── mtproto/             # MTProto Fake-TLS + Hex32, AES-CTR, обход DPI
│   ├── admin/               # HTTP Web-админка и REST API
│   ├── users/               # Хранение и аутентификация пользователей
│   ├── agent/               # Обратный агент и туннелирование трафика
│   └── tor/                 # Tor SOCKS5 клиент и IsolateSOCKSAuth
├── test/
│   └── all_test.go          # Полный набор интеграционных тестов
├── config.json              # Конфиг socks-control по умолчанию
├── users.json               # База SOCKS5 пользователей
├── mtproto_users.json       # База MTProto клиентов
├── socks-control.exe        # Скомпилированный бинарник для Windows
├── socks-control-linux-amd64# Скомпилированный бинарник для Linux
├── socks-reverse.exe        # Reverse-агент для Windows
├── socks-reverse-linux-amd64# Reverse-агент для Linux
├── start-control.bat/.sh    # Скрипты запуска control-сервера
└── start-reverse.bat/.sh    # Скрипты запуска reverse-агента
```

---

## 🚀 Сборка и запуск

### 1. Запуск на Windows

Запуск основного сервера:
```cmd
socks-control.exe --config config.json
# Или дважды кликните start-control.bat
```

Запуск reverse-агента на удаленной ноде:
```cmd
socks-reverse.exe --host IP_CONTROL_СЕРВЕРА --port 9000 --token SecretProxyToken2026! --agent-id node-1
# Или с Fake-TLS:
socks-reverse.exe --host IP_CONTROL_СЕРВЕРА --port 9000 --token SecretProxyToken2026! --agent-id node-1 --fake-tls --fake-tls-domain google.com
```

### 2. Запуск на Linux / Ubuntu VPS

1. Скопируйте файлы на сервер в `/opt/socks-control`:
   ```bash
   sudo mkdir -p /opt/socks-control
   sudo cp socks-control-linux-amd64 /opt/socks-control/
   sudo cp config.json /opt/socks-control/
   sudo cp users.json /opt/socks-control/ 2>/dev/null || true
   sudo cp mtproto_users.json /opt/socks-control/ 2>/dev/null || true
   sudo chmod +x /opt/socks-control/socks-control-linux-amd64
   ```

2. Установите systemd-сервис:
   ```bash
   sudo cp socks-control.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now socks-control
   ```

3. Просмотр логов:
   ```bash
   sudo journalctl -u socks-control -f
   ```

---

## 🧪 Запуск тестов

Для запуска всех тестов:
```bash
go test -v ./test/...
```
Тест проверяет:
- SOCKS5 TCP CONNECT, UDP ASSOCIATE, BIND.
- SOCKS4 и SOCKS4a с удаленным резолвом доменов.
- HTTP CONNECT и HTTP forward proxying.
- Строгую аутентификацию и отсечение неавторизованных запросов.
- MTProto Fake-TLS 1.3 рукопожатие с проверкой HMAC-SHA256 и ServerHello.
- Ротацию нод персонально для каждого пользователя.
- Работу веб-админки и REST API.
