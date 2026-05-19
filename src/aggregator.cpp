#include "aggregator.h"

void Aggregator::add(const stack_event &event) {
    total_++;
    // TODO: key on stack ID and accumulate per-stack counts.
}

size_t Aggregator::total() const {
    return total_;
}
