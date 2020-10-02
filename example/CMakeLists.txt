cmake_minimum_required(VERSION 3.13)
project(example NONE)

add_executable(client client.cc)
add_executable(server server.cc)
add_executable(keylogger keylog.cc)

find_package(Threads REQUIRED)
find_package(Protobuf REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})

target_include_directories(client
    PUBLIC
    ${CMAKE_BINARY_DIR}/proto)

target_include_directories(server
    PUBLIC
    ${CMAKE_BINARY_DIR}/proto)
    
target_link_libraries(client
    PUBLIC
    ${PROTOBUF_LIBRARIES}
    ${CMAKE_BINARY_DIR}/proto/libsockproto.a)

target_link_libraries(server
    PUBLIC
    ${PROTOBUF_LIBRARIES}
    ${CMAKE_BINARY_DIR}/proto/libsockproto.a)

target_link_libraries(keylogger Threads::Threads)
