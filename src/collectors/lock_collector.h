#pragma once

#include "lock.h"
#include <utility>
#include <vector>

struct lock_bpf;

// Loads the lock BPF program and lets the kernel accumulate contention stats
// into a per-CPU hash map. Call start() once, then snapshot_and_clear()
// periodically from the heartbeat thread to drain accumulated data.
class LockCollector {
public:
    LockCollector();
    ~LockCollector();

    bool start();
    void stop();

    int stack_traces_fd() const;

    // Iterates lock_stats, sums per-CPU values into a single entry per key,
    // deletes each entry from the map, and returns the results.
    std::vector<std::pair<lock_stat_key, lock_stat_val>> snapshot_and_clear();

    // Deletes all entries from lock_stack_traces. Call this after resolving
    // all stack IDs from the last snapshot, so the map doesn't fill up.
    void clear_stack_traces();

private:
    struct lock_bpf *skel_       = nullptr;
    int stack_traces_fd_         = -1;
    int lock_stats_fd_           = -1;
};
