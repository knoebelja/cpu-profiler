#pragma once

#include <cstddef>
#include <map>
#include <vector>
#include "../bpf/profiler.h"

// Accumulates stack samples and tracks how often each unique
// pid+stack combination appears. Used to produce ranked summaries
// and flame graph data.
class Aggregator {
public:
    void add(const stack_event &event);

    // Returns total number of samples collected so far.
    size_t total() const;

private:
    size_t total_ = 0;

    // TODO: store per-stack counts keyed by stack ID.
    // For now just counts total samples.
};
