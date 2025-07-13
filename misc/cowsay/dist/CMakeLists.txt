cmake_minimum_required(VERSION 3.18.1)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# add extern/luau
add_subdirectory(extern/luau)
project(luactf VERSION 0.1.0)

add_executable(${PROJECT_NAME} src/main.cpp
    src/cowsayLib.cpp src/cowsayLib.h
    src/security.cpp src/security.h
    src/safeLua.cpp src/safeLua.h)
target_link_libraries(${PROJECT_NAME} Luau.Compiler Luau.VM)
