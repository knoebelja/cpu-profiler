#include "output.h"
#include <cstdio>

void print_event(const stack_event &event, const SymbolResolver &resolver, int stack_traces_fd) {
    printf("[cpu=%d] pid=%-6u comm=%-16s ts=%llu\n",
           event.cpu, event.pid, event.comm, event.timestamp_ns);
    
    auto frames = resolver.resolve_kernel_stack(stack_traces_fd, event.kernel_stack_id);

    for (const auto &frame : frames) {
        printf("  %s\n", frame.c_str());
    }
}
