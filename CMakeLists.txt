cmake_minimum_required(VERSION 3.13)
project(sockpuppet)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -Wextra")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
add_subdirectory(proto)
add_subdirectory(example)
add_subdirectory(include)
add_subdirectory(tests)
