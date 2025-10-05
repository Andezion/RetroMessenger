cmake_minimum_required(VERSION 4.0)
project(Messenger)

set(CMAKE_CXX_STANDARD 11)

find_package(wxWidgets REQUIRED COMPONENTS core base gl net)
include(${wxWidgets_USE_FILE})

include_directories(${wxWidgets_INCLUDE_DIRS})

add_executable(Messenger main.cpp)
target_link_libraries(Messenger ${wxWidgets_LIBRARIES})