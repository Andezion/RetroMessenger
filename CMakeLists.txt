cmake_minimum_required(VERSION 3.10)
project(Messenger CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# wxWidgets
find_package(wxWidgets REQUIRED COMPONENTS core base net)
include(${wxWidgets_USE_FILE})

# Boost.Asio — header-only, но нужны потоки
find_package(Threads REQUIRED)

# === Клиент ===
add_executable(Messenger
        main.cpp        # твой GUI (wxWidgets + EchoClient)
)

target_link_libraries(Messenger
        ${wxWidgets_LIBRARIES}
        Threads::Threads
)

# === Сервер ===
add_executable(EchoServer
        server.cpp      # твой простой boost::asio TCP echo сервер
)

target_link_libraries(EchoServer
        Threads::Threads
)
