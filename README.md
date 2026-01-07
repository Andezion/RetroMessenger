# RetroMessenger

Простой мессенджер на C++ с графическим интерфейсом на базе wxWidgets и сетевым взаимодействием через Boost.Asio.

## Компоненты

- **Messenger** - GUI клиент на wxWidgets
- **EchoServer** - многопользовательский чат-сервер

## Сборка

```bash
cd build
cmake ..
make
```

## Запуск

### Вариант 1: Через wrapper-скрипты (рекомендуется)

```bash
# Запуск сервера (по умолчанию порт 12345)
./run_server.sh

# Или с указанием порта
./run_server.sh 8080

# Запуск клиента в другом терминале
./run_messenger.sh
```

### Вариант 2: Напрямую из build/

```bash
# Сервер
cd build
./EchoServer [port]

# Клиент (требует очистку snap переменных при запуске из VSCode)
cd build
./Messenger
```

## Зависимости

- **CMake** >= 3.10
- **C++17** компилятор (g++, clang++)
- **wxWidgets** >= 3.0
- **Boost** (components: system)
- **Threads**

### Установка зависимостей

Ubuntu/Debian:
```bash
sudo apt install build-essential cmake libwxgtk3.0-gtk3-dev libboost-system-dev
```

## Использование

1. Запустите сервер: `./run_server.sh`
2. Запустите один или несколько клиентов: `./run_messenger.sh`
3. В GUI клиенте введите Host: `127.0.0.1`, Port: `12345`
4. Нажмите "Connect"
5. Пишите сообщения - они будут рассылаться всем подключенным клиентам

## Архитектура

- **Клиент**: асинхронный сетевой клиент на Boost.Asio с GUI на wxWidgets
- **Сервер**: асинхронный многопользовательский сервер с broadcast сообщений
- **Протокол**: текстовые сообщения, разделенные символом новой строки `\n`

