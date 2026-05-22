#pragma once

#include "profiler.h"
#include <mutex>
#include <vector>

// lock_guard auto releases when it is out of scope
class Buffer {
public:
  void push(const stack_event &event) {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back(event);
  }

  // Swap out accumulated events and start a new buffer.
  std::vector<stack_event> swap_out() {
    std::vector<stack_event> snapshot;
    std::lock_guard<std::mutex> lock(mutex_);
    std::swap(snapshot, events_);
    return snapshot;
  }

private:
  std::vector<stack_event> events_;
  std::mutex mutex_;
};
