#pragma once

#include "../bpf/profiler.h"
#include "symbols.h"
// Formats and prints a single stack_event to stdout.
// resolver is used to look up kernel symbol names from stack IDs.
// resolve is non-const because resolving user stacks lazily caches /proc/PID/maps
void print_event(const stack_event &event, SymbolResolver &resolver, int stack_traces_fd);
