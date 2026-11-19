cmake_minimum_required(VERSION 3.16)
project(npcap_frame_sniffer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(ethernet STATIC src/ethernet.cpp)
target_include_directories(ethernet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(capture STATIC src/capture.cpp)
target_include_directories(capture PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(npcap_sniffer src/main.cpp)
target_link_libraries(npcap_sniffer PRIVATE ethernet capture)

enable_testing()
add_executable(ethernet_tests tests/ethernet_tests.cpp)
target_link_libraries(ethernet_tests PRIVATE ethernet)
add_test(NAME ethernet_parser COMMAND ethernet_tests)

if(WIN32)
    # NPcap SDK: https://npcap.com/#download
    # Example: cmake -S . -B build -A x64 -DNPCAP_SDK_DIR="C:/npcap-sdk-1.15"
    set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}" CACHE PATH "Npcap SDK root directory")

    find_path(NPCAP_INCLUDE_DIR
        NAMES pcap.h
        HINTS
            "${NPCAP_SDK_DIR}/Include"
            "$ENV{NPCAP_SDK_DIR}/Include"
        DOC "Npcap SDK include directory"
    )
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
        set(NPCAP_LIB_SUBDIR "Lib/ARM64")
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(NPCAP_LIB_SUBDIR "Lib/x64")
    else()
        set(NPCAP_LIB_SUBDIR "Lib")
    endif()

    find_library(NPCAP_WPCAP_LIBRARY
        NAMES wpcap
        HINTS
            "${NPCAP_SDK_DIR}/${NPCAP_LIB_SUBDIR}"
            "$ENV{NPCAP_SDK_DIR}/${NPCAP_LIB_SUBDIR}"
            "${NPCAP_SDK_DIR}/Lib"
            "$ENV{NPCAP_SDK_DIR}/Lib"
        DOC "Npcap wpcap import library"
    )

    if(NOT NPCAP_INCLUDE_DIR OR NOT NPCAP_WPCAP_LIBRARY)
        message(FATAL_ERROR
            "Npcap SDK was not found. Download it from https://npcap.com/#download "
            "and configure with -DNPCAP_SDK_DIR=<path to npcap-sdk>.")
    endif()

    target_include_directories(capture PUBLIC ${NPCAP_INCLUDE_DIR})
    target_link_libraries(capture PUBLIC ${NPCAP_WPCAP_LIBRARY} ws2_32)

    if(MSVC)
        target_compile_options(npcap_sniffer PRIVATE /W4 /permissive- /utf-8)
        target_compile_options(ethernet PRIVATE /W4 /permissive- /utf-8)
        target_compile_options(capture PRIVATE /W4 /permissive- /utf-8)
        target_compile_options(ethernet_tests PRIVATE /W4 /permissive- /utf-8)
        target_compile_definitions(npcap_sniffer PRIVATE
            NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
    endif()
else()
    find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)

    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR
            "libpcap was not found. Install libpcap development files "
            "(macOS: built in; Debian/Ubuntu: apt install libpcap-dev).")
    endif()

    target_include_directories(capture PUBLIC ${PCAP_INCLUDE_DIR})
    target_link_libraries(capture PUBLIC ${PCAP_LIBRARY})

    target_compile_options(ethernet PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(capture PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(npcap_sniffer PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(ethernet_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()
