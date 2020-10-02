cmake_minimum_required(VERSION 3.13)
project(tests NONE)

include(../cmake/FindPCAP.cmake)

find_package(GTest REQUIRED)
find_package(Protobuf REQUIRED)

add_compile_definitions(DEBUG)
include_directories(${GTEST_INCLUDE_DIRS} ${GMOCK_INCLUDE_DIRS} ${Protobuf_INCLUDE_DIRS})
add_executable(tests main.cc server.cc client.cc recon/collect/arp.cc recon/collect/sniff.cc recon/scan/syn.cc util/privs.cc)

target_link_libraries(tests ${GTEST_LIBRARIES} ${PROTOBUF_LIBRARIES} ${PCAP_LIBRARY}  gmock gmock_main pthread ${CMAKE_BINARY_DIR}/proto/libsockproto.a)

target_include_directories(tests
    PUBLIC
    ${CMAKE_BINARY_DIR}/proto)

