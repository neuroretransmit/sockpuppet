cmake_minimum_required(VERSION 3.13)
project(example NONE)

add_executable(client client.cc)
add_executable(server server.cc)

find_package(Protobuf REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})

target_include_directories(client
    PUBLIC
    ${PROTOBUF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(client
    PUBLIC
    ${PROTOBUF_LIBRARIES}
    ${CMAKE_BINARY_DIR}/proto/libsockproto.a)

target_link_libraries(server
    PUBLIC
    ${PROTOBUF_LIBRARIES}
    ${CMAKE_BINARY_DIR}/proto/libsockproto.a)
