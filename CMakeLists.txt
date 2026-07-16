cmake_minimum_required(VERSION 3.14)
project(learning-profilers)

set(CMAKE_CXX_STANDARD 17)

set(PERF_BPF_SOURCE ${CMAKE_SOURCE_DIR}/bpf/perf.bpf.c)
set(PERF_BPF_OBJECT ${CMAKE_BINARY_DIR}/perf.bpf.o)
set(PERF_BPF_SKEL   ${CMAKE_BINARY_DIR}/perf.skel.h)

add_custom_command(
    OUTPUT ${PERF_BPF_OBJECT}
    COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_X86
            -I/usr/include/x86_64-linux-gnu
            -c ${PERF_BPF_SOURCE} -o ${PERF_BPF_OBJECT}
    DEPENDS ${PERF_BPF_SOURCE} ${CMAKE_SOURCE_DIR}/bpf/perf.h
)

add_custom_command(
    OUTPUT ${PERF_BPF_SKEL}
    COMMAND bpftool gen skeleton ${PERF_BPF_OBJECT} > ${PERF_BPF_SKEL}
    DEPENDS ${PERF_BPF_OBJECT}
)

add_custom_target(perf_bpf_skel DEPENDS ${PERF_BPF_SKEL})

set(LOCK_BPF_SOURCE ${CMAKE_SOURCE_DIR}/bpf/lock.bpf.c)
set(LOCK_BPF_OBJECT ${CMAKE_BINARY_DIR}/lock.bpf.o)
set(LOCK_BPF_SKEL   ${CMAKE_BINARY_DIR}/lock.skel.h)

add_custom_command(
    OUTPUT ${LOCK_BPF_OBJECT}
    COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_X86
            -I/usr/include/x86_64-linux-gnu
            -c ${LOCK_BPF_SOURCE} -o ${LOCK_BPF_OBJECT}
    DEPENDS ${LOCK_BPF_SOURCE} ${CMAKE_SOURCE_DIR}/bpf/lock.h
)

add_custom_command(
    OUTPUT ${LOCK_BPF_SKEL}
    COMMAND bpftool gen skeleton ${LOCK_BPF_OBJECT} > ${LOCK_BPF_SKEL}
    DEPENDS ${LOCK_BPF_OBJECT}
)

add_custom_target(lock_bpf_skel DEPENDS ${LOCK_BPF_SKEL})

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
    src/collectors/perf_collector.cpp
    src/collectors/lock_collector.cpp
    src/symbols.cpp
    src/aggregators/thread_activity.cpp
    src/aggregators/kernel_dictionary.cpp
    src/aggregators/call_stack.cpp
    src/aggregators/lock_contention.cpp
)

add_dependencies(profiler perf_bpf_skel lock_bpf_skel)

target_include_directories(profiler PRIVATE
    src
    src/collectors
    src/aggregators
    src/profilers
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
    src/collectors/perf_collector.cpp
    src/symbols.cpp
)

add_dependencies(collect_symbols perf_bpf_skel)

target_include_directories(collect_symbols PRIVATE
    src
    src/collectors
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

add_executable(sim sim/main.cpp)
target_compile_features(sim PRIVATE cxx_std_17)
target_link_libraries(sim PRIVATE pthread)

find_program(CLANG_FORMAT clang-format)
if(CLANG_FORMAT)
    file(GLOB_RECURSE ALL_SOURCE_FILES src/*.cpp src/*.h)
    add_custom_target(format
        COMMAND ${CLANG_FORMAT} -i ${ALL_SOURCE_FILES}
        COMMENT "Formatting source files"
    )
endif()
