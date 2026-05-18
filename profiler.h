#pragma once

// Maximum number of stack frames we'll capture per sample.
// Deeper stacks are truncated. 32 is a reasonable default —
// deep enough to be useful, shallow enough to keep map memory bounded.
#define MAX_STACK_DEPTH 32

// This struct is the unit of data passed from the BPF kernel program
// to userspace each time the CPU is sampled. Both sides include this
// header so the struct layout is identical in kernel and userspace.
struct stack_event {
    __u32 pid;              // Process ID that was on-CPU at sample time
    __u32 cpu;              // Which CPU core was sampled
    __u64 timestamp_ns;     // Nanoseconds since boot (from bpf_ktime_get_ns)
    __s32 kernel_stack_id;  // Key into the stack_traces BPF map for kernel frames
    __s32 user_stack_id;    // Key into the stack_traces BPF map for userspace frames
    char comm[16];          // Process name (Linux kernel caps this at 16 chars)
};
