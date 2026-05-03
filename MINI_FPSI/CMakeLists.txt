cmake_minimum_required(VERSION 3.15)
project(MINI_FPSI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)

find_package(libOTe REQUIRED COMPONENTS
    std_20
    boost
    iknp
    silentot
    softspoken_ot
)

message(STATUS "ENABLE_IKNP          = ${ENABLE_IKNP}")
message(STATUS "ENABLE_SILENTOT      = ${ENABLE_SILENTOT}")
message(STATUS "ENABLE_SOFTSPOKEN_OT = ${ENABLE_SOFTSPOKEN_OT}")

add_executable(Alice src/Alice.cpp)
add_executable(Bob   src/Bob.cpp)

foreach(_tgt Alice Bob)
    target_include_directories(${_tgt} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(${_tgt} PRIVATE oc::libOTe Threads::Threads)

    if(ENABLE_IKNP)
        target_compile_definitions(${_tgt} PRIVATE ENABLE_IKNP)
    endif()
    if(ENABLE_SILENTOT)
        target_compile_definitions(${_tgt} PRIVATE ENABLE_SILENTOT)
    endif()
    if(ENABLE_SOFTSPOKEN_OT)
        target_compile_definitions(${_tgt} PRIVATE ENABLE_SOFTSPOKEN_OT)
    endif()
endforeach()