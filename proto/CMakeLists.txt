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
# 
# add_custom_target(CopyAndRename
#     COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/commands.pb.* ${CMAKE_SOURCE_DIR}/include/sockpuppet/proto
# )

set(PROTOBUF_HDRS 
    ${CMAKE_BINARY_DIR}/proto/commands.pb.h PARENT_SCOPE)
set(PROTOBUF_SRCS 
    ${CMAKE_BINARY_DIR}/proto/commands.pb.cc PARENT_SCOPE)

install(TARGETS sockproto DESTINATION lib)
