# Intermediate build artifacts (BPF object file, generated skeleton header)
# go in .output/ to keep the root directory clean.
OUTPUT := .output
CLANG := clang

# -g: include debug info (required for BTF, which enables CO-RE)
# -Wall: enable all warnings
CXXFLAGS := -g -Wall -std=c++17

# Ask pkg-config for the right include paths and linker flags for libbpf
# on this system, rather than hardcoding them.
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)

SRCS := src/main.cpp src/collector.cpp src/aggregator.cpp src/symbols.cpp src/output.cpp

.PHONY: all clean

all: profiler

# Create the output directory if it doesn't exist.
$(OUTPUT):
	mkdir -p $(OUTPUT)

# Step 1: Compile the BPF kernel program to BPF bytecode.
# -target bpf: compile for the BPF virtual machine, not the host CPU
# -D__TARGET_ARCH_x86: tells BPF tracing helpers which architecture we're on
# -I/usr/include/x86_64-linux-gnu: kernel type headers (u32, u64, etc.)
# -O2: BPF verifier requires optimized code; unoptimized BPF often fails verification
$(OUTPUT)/profiler.bpf.o: bpf/profiler.bpf.c bpf/profiler.h | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_X86 \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c bpf/profiler.bpf.c -o $@

# Step 2: Generate the BPF skeleton header from the compiled object.
# bpftool inspects the BPF object and generates a typed C API specific to
# our program — structs, open/load/attach/destroy functions, and map accessors.
$(OUTPUT)/profiler.skel.h: $(OUTPUT)/profiler.bpf.o
	bpftool gen skeleton $< > $@

# Step 3: Compile all userspace C++ sources, linking against libbpf, libelf, and zlib.
# -I$(OUTPUT) makes the generated profiler.skel.h visible to the compiler.
profiler: $(SRCS) $(OUTPUT)/profiler.skel.h bpf/profiler.h
	$(CXX) $(CXXFLAGS) $(LIBBPF_CFLAGS) \
		-Isrc -Ibpf -I$(OUTPUT) \
		$(SRCS) -o profiler \
		$(LIBBPF_LIBS) -lelf -lz

# Remove all build artifacts.
clean:
	rm -rf $(OUTPUT) profiler
