#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct resolved_event {
  uint32_t pid;
  uint32_t cpu;
  int32_t kernel_stack_id;
  int32_t user_stack_id;
  char comm[16];
  std::vector<std::string> kernel_syms;
};
