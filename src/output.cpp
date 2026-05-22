#include "output.h"
#include <cstdio>

void print_event(const stack_event &event, SymbolResolver &resolver,
                 int stack_traces_fd) {
  printf("[cpu=%d] pid=%-6u comm=%-16s ts=%llu\n", event.cpu, event.pid,
         event.comm, event.timestamp_ns);

  auto frames =
      resolver.resolve_kernel_stack(stack_traces_fd, event.kernel_stack_id);
  for (const auto &frame : frames) {
    printf(" [kernel] %s\n", frame.c_str());
  }

  // These show as "path+offset" for now since we haven't parsed ELF symbol
  // tables yet.
  auto user_frames = resolver.resolve_user_stack(
      stack_traces_fd, event.user_stack_id, event.pid);
  for (const auto &frame : user_frames) {
    printf(" [user] %s\n", frame.c_str());
  }
}
