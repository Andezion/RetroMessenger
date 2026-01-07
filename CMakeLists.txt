cmake_minimum_required(VERSION 3.10)
project(Messenger CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(wxWidgets REQUIRED COMPONENTS core base net)
include(${wxWidgets_USE_FILE})

find_package(Boost REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)

add_executable(Messenger
        main.cpp
)

target_link_libraries(Messenger
        ${wxWidgets_LIBRARIES}
        Boost::system
        Threads::Threads
)

add_executable(EchoServer
        server.cpp
)

target_link_libraries(EchoServer
        Boost::system
        Threads::Threads
)
