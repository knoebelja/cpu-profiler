#pragma once
#include <linux/types.h>

#define LOCK_MAX_STACK_DEPTH 127

// stored for each in-flight wait; keyed by tid in pending_waits
// uaddr/tgid/holder_tid are stashed here because the exit probe doesn't have them
struct contention_start {
    __u64 timestamp_ns;
    __u64 uaddr;
    __u32 tgid;
    __u32 holder_tid;
    __s32 user_stack_id;
};

// stored when a thread calls futex(FUTEX_WAKE) — captures the holder's unlock
// stack so we can correlate it with the waiter that subsequently wakes up
struct wake_info {
    __s32 stack_id;
    __u32 tid;
};

// key for pending_wakes map — (tgid, uaddr) to avoid collisions across processes
// that happen to have the same virtual address for their mutex
struct wake_key {
    __u64 uaddr;
    __u32 tgid;
    __u32 _pad;
};

// key into lock_stats — one entry per unique (waiter call site, holder call site, lock)
struct lock_stat_key {
    __u64 uaddr;
    __s32 waiter_stack_id;
    __s32 holder_stack_id;
};

// accumulated stats per unique key tuple
// lives in a BPF_MAP_TYPE_PERCPU_HASH; userspace sums across CPUs on read
struct lock_stat_val {
    __u64 total_wait_ns;
    __u64 count;
    __u32 tgid;
    __u32 holder_tid;
    char comm[16];
};
