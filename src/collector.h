#pragma once

#include "../bpf/profiler.h"
#include <functional>

// Callback type invoked for each CPU sample received from the kernel.
using EventCallback = std::function<void(const stack_event &)>;

// Manages the BPF program lifecycle and perf ring buffer.
// Call start() to begin sampling; it blocks until stop() is called
// from a signal handler or another thread.
class Collector {
public:
  // sample_freq: how many times per second to sample each CPU (99 is typical)
  Collector(int sample_freq, EventCallback cb);
  ~Collector();

  bool start(); // loads BPF, opens perf events, polls until stopped
  void stop();  // signals the event loop to exit

  int stack_traces_fd() const;

private:
  int sample_freq_;
  EventCallback cb_;
  bool running_ = false;

  int stack_traces_fd_ = -1;
};
