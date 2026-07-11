#pragma once

#include <cstdint>
#include <string>
#include <vector>

// All symbol resolution happens in the heartbeat before aggregators run,
// so aggregators receive named stacks directly and need no resolver dependency.
struct resolved_event {
  uint32_t pid;
  uint32_t cpu;
  int32_t kernel_stack_id;
  int32_t user_stack_id;
  char comm[16];
  std::vector<std::string> kernel_syms;
  std::vector<std::string> user_syms;
  uint64_t timestamp_ms = 0; // ms since Unix epoch, set when event is resolved
};
