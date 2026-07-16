#pragma once

#include "lock.h"
#include "resolved_event.h"
#include <string>
#include <vector>

struct resolved_lock_entry {
    lock_stat_key key;
    lock_stat_val val;
    std::vector<std::string> waiter_frames;
    std::vector<std::string> holder_frames;
};

struct heartbeat_data {
    std::vector<resolved_event> events;
    std::vector<resolved_lock_entry> lock_stats;
};
