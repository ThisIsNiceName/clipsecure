cmake_minimum_required(VERSION 3.10)
project(clipsecure VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ========== SDK DLL ==========
add_library(clipsecure SHARED
    src/ClipSecure.cpp
    src/state.h
    src/state.cpp
    src/crypto.h
    src/crypto.cpp
    src/hook.h
    src/hook.cpp
)

target_include_directories(clipsecure
    PUBLIC  include
    PRIVATE src
)

target_link_libraries(clipsecure
    user32
    bcrypt
    ${CMAKE_SOURCE_DIR}/include-lib/detours.lib
)

# 导出 DLL 符号
target_compile_definitions(clipsecure PRIVATE CLIPSECURE_EXPORTS)

# DLL 使用默认输出目录（build/Release/）

# ========== Demo 程序 ==========
add_executable(demo
    demo/demo.cpp
)

target_link_libraries(demo
    clipsecure
)