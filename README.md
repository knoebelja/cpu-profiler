# CPU Profiler

A CPU profiler built with eBPF and C++. Samples all CPU cores at 99hz using perf events, capturing kernel and userspace call stacks via a BPF ring buffer.

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

Press Ctrl+C to stop. Output shows the process name, PID, CPU core, and timestamp for each sample.
