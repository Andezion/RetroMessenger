cmake_minimum_required(VERSION 3.10)
project(RetroMessenger CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(wxWidgets_CONFIG_EXECUTABLE /usr/bin/wx-config)

find_package(wxWidgets REQUIRED COMPONENTS core base)
include(${wxWidgets_USE_FILE})
include_directories(${wxWidgets_INCLUDE_DIRS}) 

find_package(Boost REQUIRED COMPONENTS filesystem system)
include_directories(${Boost_INCLUDE_DIRS})

add_executable(RetroMessenger main.cpp)
target_link_libraries(RetroMessenger ${wxWidgets_LIBRARIES} ${Boost_LIBRARIES})

add_executable(ChatServer server.cpp)
target_link_libraries(ChatServer ${wxWidgets_LIBRARIES} ${Boost_LIBRARIES})
