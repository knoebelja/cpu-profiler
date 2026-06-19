#pragma once
#include <linux/types.h>

#define MAX_STACK_DEPTH 127


// when a thread calls futex(FUTEX_WAIT)
// we need to remember who was waiting on which lock (uaddr)
// so we can match it when futex returns
// tgid is the process, tid is the specific thread
// multiple threads in the same process can be blocked
// on different locks simultaneously
struct contention_key {
    __u32 tgid;
    __u32 tid;
    __u64 uaddr;
};

// stored for each in-flight wait
// when it started and what the call stack
// looked liked like at that moment
// we capture on entry (not exit) because
// the thread is actually in the code path
// that tried to acquire the lock
// at that moment
struct contention_start {
    __u64 timestamp_ns;
    __s32 user_stack_id;
};

// sent to userspace when contention resolves
// wait_ns is duration the thread is blocked
// this is basically what we aggregate and display
struct lock_event {
    __u32 tgid;
    __u32 tid;
    __u64 uaddr;
    __u64 wait_ns;
    __s32 user_stack_id;
    char comm[16];
};

