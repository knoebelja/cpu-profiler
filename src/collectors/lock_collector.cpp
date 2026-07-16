#include "lock_collector.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstdio>
#include <cstring>
#include <vector>

#include "lock.skel.h"

LockCollector::LockCollector() {}

LockCollector::~LockCollector() {
    stop();
}

bool LockCollector::start() {
    skel_ = lock_bpf__open_and_load();
    if (!skel_) {
        fprintf(stderr, "Failed to open and load lock BPF skeleton\n");
        return false;
    }

    if (lock_bpf__attach(skel_) < 0) {
        fprintf(stderr, "Failed to attach lock BPF programs\n");
        lock_bpf__destroy(skel_);
        skel_ = nullptr;
        return false;
    }

    stack_traces_fd_ = bpf_map__fd(skel_->maps.lock_stack_traces);
    lock_stats_fd_   = bpf_map__fd(skel_->maps.lock_stats);
    return true;
}

void LockCollector::stop() {
    if (skel_) {
        lock_bpf__destroy(skel_);
        skel_ = nullptr;
    }
}

int LockCollector::stack_traces_fd() const { return stack_traces_fd_; }

std::vector<std::pair<lock_stat_key, lock_stat_val>> LockCollector::snapshot_and_clear() {
    std::vector<std::pair<lock_stat_key, lock_stat_val>> results;
    if (lock_stats_fd_ < 0)
        return results;

    int num_cpus = libbpf_num_possible_cpus();
    std::vector<lock_stat_val> cpu_vals(num_cpus);

    // Phase 1: collect all keys without touching the map
    std::vector<lock_stat_key> keys;
    lock_stat_key next_key;
    lock_stat_key *prev_key = nullptr;
    while (bpf_map_get_next_key(lock_stats_fd_, prev_key, &next_key) == 0) {
        keys.push_back(next_key);
        prev_key = &keys.back();
    }

    // Phase 2: read, sum across CPUs, delete
    for (auto &k : keys) {
        if (bpf_map_lookup_elem(lock_stats_fd_, &k, cpu_vals.data()) < 0)
            continue;

        lock_stat_val total = {};
        for (int i = 0; i < num_cpus; i++) {
            total.total_wait_ns += cpu_vals[i].total_wait_ns;
            total.count         += cpu_vals[i].count;
            // take metadata from whichever CPU slot has data
            if (cpu_vals[i].count > 0 && total.tgid == 0) {
                total.tgid       = cpu_vals[i].tgid;
                total.holder_tid = cpu_vals[i].holder_tid;
                memcpy(total.comm, cpu_vals[i].comm, sizeof(total.comm));
            }
        }

        if (total.count > 0)
            results.push_back({k, total});

        bpf_map_delete_elem(lock_stats_fd_, &k);
    }

    return results;
}

void LockCollector::clear_stack_traces() {
    if (stack_traces_fd_ < 0)
        return;

    // Two-phase: collect keys first, then delete, to avoid restart-on-delete.
    std::vector<int32_t> keys;
    int32_t next_key;
    int32_t *prev_key = nullptr;
    while (bpf_map_get_next_key(stack_traces_fd_, prev_key, &next_key) == 0) {
        keys.push_back(next_key);
        prev_key = &keys.back();
    }
    for (auto &k : keys)
        bpf_map_delete_elem(stack_traces_fd_, &k);
}
