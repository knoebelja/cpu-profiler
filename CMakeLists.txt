cmake_minimum_required(VERSION 3.14)
project(cpu-profiler)

set(CMAKE_CXX_STANDARD 17)

set(BPF_SOURCE ${CMAKE_SOURCE_DIR}/bpf/profiler.bpf.c)
set(BPF_OBJECT ${CMAKE_BINARY_DIR}/profiler.bpf.o)
set(BPF_SKEL   ${CMAKE_BINARY_DIR}/profiler.skel.h)

add_custom_command(
    OUTPUT ${BPF_OBJECT}
    COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_X86
            -I/usr/include/x86_64-linux-gnu
            -c ${BPF_SOURCE} -o ${BPF_OBJECT}
    DEPENDS ${BPF_SOURCE} ${CMAKE_SOURCE_DIR}/bpf/profiler.h
)

add_custom_command(
    OUTPUT ${BPF_SKEL}
    COMMAND bpftool gen skeleton ${BPF_OBJECT} > ${BPF_SKEL}
    DEPENDS ${BPF_OBJECT}
)

add_custom_target(bpf_skel DEPENDS ${BPF_SKEL})

include(FetchContent)

FetchContent_Declare(
    ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
    GIT_TAG v5.0.0
)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json
    GIT_TAG v3.11.3
)

FetchContent_MakeAvailable(ftxui nlohmann_json)

add_executable(profiler
    src/main.cpp
    src/collector.cpp
    src/symbols.cpp
    src/output.cpp
    src/aggregators/thread_activity.cpp
    src/aggregators/kernel_dictionary.cpp
)

add_dependencies(profiler bpf_skel)

target_include_directories(profiler PRIVATE
    src
    src/aggregators
    bpf
    ${CMAKE_BINARY_DIR}
)

target_compile_definitions(profiler PRIVATE SOURCE_DIR="${CMAKE_SOURCE_DIR}")

target_link_libraries(profiler PRIVATE
    bpf
    elf
    z
    ftxui::screen
    ftxui::dom
    ftxui::component
    nlohmann_json::nlohmann_json
)

add_executable(collect_symbols
    tools/collect_symbols.cpp
    src/collector.cpp
    src/symbols.cpp
)

add_dependencies(collect_symbols bpf_skel)

target_include_directories(collect_symbols PRIVATE
    src
    bpf
    ${CMAKE_BINARY_DIR}
)

target_compile_definitions(collect_symbols PRIVATE SOURCE_DIR="${CMAKE_SOURCE_DIR}")

target_link_libraries(collect_symbols PRIVATE
    bpf
    elf
    z
    nlohmann_json::nlohmann_json
)

find_program(CLANG_FORMAT clang-format)
if(CLANG_FORMAT)
    file(GLOB_RECURSE ALL_SOURCE_FILES src/*.cpp src/*.h)
    add_custom_target(format
        COMMAND ${CLANG_FORMAT} -i ${ALL_SOURCE_FILES}
        COMMENT "Formatting source files"
    )
endif()
