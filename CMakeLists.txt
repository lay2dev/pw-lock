cmake_minimum_required(VERSION 3.12)
project(pw-lock C)
set(CMAKE_C_STANDARD 11)
# uncomment it for sanitize
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")
add_compile_options(-Wno-macro-redefined)

include_directories(deps/libecc/src)
# deps/ckb-c-std-lib
include_directories(c)
include_directories(tests/pw_webauthn_lib)
add_definitions(-DWORDSIZE=64)
add_definitions(-DWITH_STDLIB)
add_definitions(-D__unix__)
add_definitions(-DCKB_SIMULATOR)
add_definitions(-DNN_CONSISTENCY_CHECK)

add_executable(pw_webauthn_lib tests/pw_webauthn_lib/main_test.c)

