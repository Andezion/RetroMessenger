cmake_minimum_required(VERSION 3.10)
project(RetroMessenger CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(wxWidgets REQUIRED COMPONENTS core base)
include(${wxWidgets_USE_FILE})

find_package(Boost REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)

add_executable(RetroMessenger main.cpp)

target_link_libraries(RetroMessenger
        ${wxWidgets_LIBRARIES}
        Boost::system
        Threads::Threads
)

add_executable(ChatServer server.cpp)
target_link_libraries(ChatServer
    Boost::system
    Threads::Threads
)

