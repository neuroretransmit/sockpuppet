cmake_minimum_required(VERSION 3.5)
project(sockproto)

find_package(Protobuf REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})

protobuf_generate_cpp(
    PROTO_SRCS
    PROTO_HDRS
    commands.proto)

add_library(sockproto
    ${PROTO_SRCS}
    ${PROTO_HDRS})

target_include_directories(sockproto
    PUBLIC
    ${PROTOBUF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(sockproto
    PUBLIC
    ${PROTOBUF_LIBRARIES})

configure_file(${CMAKE_CURRENT_BINARY_DIR}/commands.pb.cc ${CMAKE_SOURCE_DIR}/include/sockpuppet/proto/commands.pb.cc COPYONLY)
configure_file(${CMAKE_CURRENT_BINARY_DIR}/commands.pb.h ${CMAKE_SOURCE_DIR}/include/sockpuppet/proto/commands.pb.h COPYONLY)


set(PROTOBUF_HDRS 
    ${CMAKE_SOURCE_DIR}/include/sockpuppet/proto/commands.pb.h PARENT_SCOPE)
set(PROTOBUF_SRCS 
    ${CMAKE_SOURCE_DIR}/include/sockpuppet/proto/commands.pb.cc PARENT_SCOPE)

install(TARGETS sockproto DESTINATION lib)
