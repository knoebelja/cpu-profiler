#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "lock.h"

#define FUTEX_WAIT           0
#define FUTEX_WAKE           1
#define FUTEX_WAIT_BITSET    9
#define FUTEX_WAKE_BITSET   10
#define FUTEX_PRIVATE_FLAG   128
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_TID_MASK       0x3fffffff

// matches the raw syscall tracepoint layout:
//   8 bytes common header | 8 bytes syscall id | args[6] as unsigned long
struct sys_enter_ctx {
    unsigned long long __unused;
    long id;
    unsigned long args[6];
};

struct sys_exit_ctx {
    unsigned long long __unused;
    long id;
    long ret;
};

// key = tid; a blocked thread can only wait on one futex at a time
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct contention_start);
    __uint(max_entries, 4096);
} pending_waits SEC(".maps");

// key = (tgid, uaddr); stores the most recent unlock stack for each lock
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct wake_key);
    __type(value, struct wake_info);
    __uint(max_entries, 4096);
} pending_wakes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, LOCK_MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 2048);
} lock_stack_traces SEC(".maps");

// per-CPU hash: each CPU accumulates independently, no atomics needed
// userspace sums all CPU slots when it reads
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct lock_stat_key);
    __type(value, struct lock_stat_val);
    __uint(max_entries, 4096);
} lock_stats SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_futex")
int handle_futex_enter(struct sys_enter_ctx *ctx)
{
    int cmd = (int)(ctx->args[1]) & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

    if (cmd == FUTEX_WAKE) {
        // The calling thread is the lock holder releasing the lock.
        // Capture their call stack so we can correlate it with blocked waiters.
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        struct wake_key wk = {};
        wk.uaddr = ctx->args[0];
        wk.tgid  = (__u32)(pid_tgid >> 32);

        struct wake_info wi = {};
        wi.stack_id = bpf_get_stackid(ctx, &lock_stack_traces, BPF_F_USER_STACK);
        wi.tid      = (__u32)pid_tgid;
        bpf_map_update_elem(&pending_wakes, &wk, &wi, BPF_ANY);
        return 0;
    }

    if (cmd != FUTEX_WAIT)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid  = (__u32)pid_tgid;
    __u32 tgid = (__u32)(pid_tgid >> 32);

    struct contention_start start = {};
    start.timestamp_ns  = bpf_ktime_get_ns();
    start.uaddr         = ctx->args[0];
    start.tgid          = tgid;
    // args[2] is the val glibc confirmed was in the futex word before the syscall;
    // the lower 30 bits are the holder's TID for glibc pthread_mutex_t
    start.holder_tid    = (__u32)ctx->args[2] & FUTEX_TID_MASK;
    start.user_stack_id = bpf_get_stackid(ctx, &lock_stack_traces, BPF_F_USER_STACK);

    bpf_map_update_elem(&pending_waits, &tid, &start, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int handle_futex_exit(struct sys_exit_ctx *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    struct contention_start *start = bpf_map_lookup_elem(&pending_waits, &tid);
    if (!start)
        return 0;

    __u64 wait_ns = bpf_ktime_get_ns() - start->timestamp_ns;

    // skip spurious wakeups and uncontended fast paths
    if (wait_ns < 10000ULL) {
        bpf_map_delete_elem(&pending_waits, &tid);
        return 0;
    }

    // look up the holder's unlock stack — may be absent if we haven't seen
    // a FUTEX_WAKE for this lock yet
    struct wake_key wk = {};
    wk.uaddr = start->uaddr;
    wk.tgid  = start->tgid;
    struct wake_info *wi = bpf_map_lookup_elem(&pending_wakes, &wk);

    struct lock_stat_key k = {};
    k.uaddr           = start->uaddr;
    k.waiter_stack_id = start->user_stack_id;
    k.holder_stack_id = wi ? wi->stack_id : -1;

    struct lock_stat_val *val = bpf_map_lookup_elem(&lock_stats, &k);
    if (val) {
        val->total_wait_ns += wait_ns;
        val->count++;
    } else {
        struct lock_stat_val new_val = {};
        new_val.total_wait_ns = wait_ns;
        new_val.count         = 1;
        new_val.tgid          = start->tgid;
        new_val.holder_tid    = wi ? wi->tid : start->holder_tid;
        bpf_get_current_comm(new_val.comm, sizeof(new_val.comm));
        bpf_map_update_elem(&lock_stats, &k, &new_val, BPF_ANY);
    }

    bpf_map_delete_elem(&pending_waits, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
