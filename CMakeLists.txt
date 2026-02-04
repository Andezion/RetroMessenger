cmake_minimum_required(VERSION 3.10)
project(RetroMessenger CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(wxWidgets_CONFIG_EXECUTABLE /usr/bin/wx-config)

find_package(wxWidgets REQUIRED COMPONENTS core base)
include(${wxWidgets_USE_FILE})
include_directories(${wxWidgets_INCLUDE_DIRS})

find_package(Boost REQUIRED COMPONENTS filesystem system)
include_directories(${Boost_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(ZSTD REQUIRED libzstd)

set(CRYPTO_SOURCES
    crypto_utils.cpp
)

set(COMPRESSION_SOURCES
    tans_compression.cpp
    compression.cpp
)

set(PROTOCOL_SOURCES
    protocol.cpp
)

set(GUI_SOURCES
    gui.cpp
)

set(MAIN_SOURCE
    main_new.cpp
)

add_executable(RetroMessenger 
    ${MAIN_SOURCE}
    ${CRYPTO_SOURCES}
    ${COMPRESSION_SOURCES}
    ${PROTOCOL_SOURCES}
    ${GUI_SOURCES}
)

target_include_directories(RetroMessenger PRIVATE ${SODIUM_INCLUDE_DIRS} ${ZSTD_INCLUDE_DIRS})
target_link_libraries(RetroMessenger ${wxWidgets_LIBRARIES} ${Boost_LIBRARIES} ${SODIUM_LIBRARIES} ${ZSTD_LIBRARIES})
