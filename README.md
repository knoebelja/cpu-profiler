# CPU Profiler

A CPU profiler built with eBPF and C++. Samples all CPU cores at 99hz using perf events, capturing kernel and userspace call stacks via a BPF ring buffer. Resolves kernel addresses to symbol names via /proc/kallsyms.

Built as a learning exercise for eBPF, Linux internals, and systems performance.

## Dependencies

```bash
sudo apt install clang libbpf-dev libelf-dev zlib1g-dev bpftool
```

## Build

```bash
make
```

## Usage

```bash
sudo ./profiler
```

Press Ctrl+C to stop. Output shows the process name, PID, CPU core, timestamp, and kernel call stack for each sample. Idle CPU samples (swapper/pid=0) are filtered out by default.

## Project Structure

```
bpf/                    # BPF kernel program
  profiler.bpf.c        # Samples CPU stacks via perf events at 99hz
  profiler.h            # Shared structs between kernel and userspace
src/                    # Userspace C++
  main.cpp              # Entry point
  collector.cpp/h       # Loads BPF, manages perf events and ring buffer
  symbols.cpp/h         # Resolves kernel addresses to function names
  aggregator.cpp/h      # Counts and tracks samples (in progress)
  output.cpp/h          # Formats and prints samples
```

## What's Next

- --no-idle flag to toggle idle sample filtering
- Userspace stack resolution via /proc/PID/maps
- Sample aggregation and frequency ranking
- Flame graph output
```
