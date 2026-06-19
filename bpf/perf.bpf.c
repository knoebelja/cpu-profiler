// This file is the BPF program that runs inside the Linux kernel.
// It is compiled to BPF bytecode (not native x86) and loaded at runtime
// by the userspace program. It fires on every CPU sample event.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>  // BPF helper function declarations (bpf_get_current_pid_tgid, etc.)
#include <bpf/bpf_tracing.h>  // Macros for attaching to tracing hooks
#include "perf.h"

// BPF map: perf event ring buffer, one slot per CPU.
// The kernel writes stack_event structs here; userspace reads them out.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// BPF map: stores raw stack frames (array of instruction pointers).
// We don't embed frames directly in stack_event — instead we store them
// here and reference them by ID. This keeps stack_event small and avoids
// duplicating identical stacks across many samples.
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));  // each frame is one 64-bit address
    __uint(max_entries, 1024);                            // max unique stacks we can store at once
} stack_traces SEC(".maps");

// SEC("perf_event") tells the kernel this function should be attached to a
// perf event hook. It fires at the sample frequency configured in userspace
// (99hz), once per CPU, giving us a statistical picture of what was running.
SEC("perf_event")
int profile_cpu(struct bpf_perf_event_data *ctx)
{
    struct stack_event event = {};  // zero-initialize so no garbage data leaks to userspace

    // bpf_get_current_pid_tgid returns a u64 with tgid in the upper 32 bits and pid in the lower.
    // We shift right to extract the tgid (what userspace calls the pid for a single-threaded process).
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.cpu = bpf_get_smp_processor_id();
    event.timestamp_ns = bpf_ktime_get_ns();  // nanoseconds since boot, monotonic

    // Record the kernel call stack into the stack_traces map and store the resulting ID.
    // Userspace can later look up this ID to get the actual instruction pointer frames.
    event.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);

    // Record the userspace call stack separately. BPF_F_USER_STACK tells the helper
    // to walk the user-mode stack rather than the kernel stack.
    event.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

    // Copy the current process name (e.g. "nginx", "python3") into the event.
    bpf_get_current_comm(event.comm, sizeof(event.comm));

    // Send the completed event to userspace via the perf ring buffer.
    // BPF_F_CURRENT_CPU means write to the ring buffer slot for this CPU.
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// BPF programs must declare a license. GPL is required to use certain kernel helpers.
char LICENSE[] SEC("license") = "GPL";
