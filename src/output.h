#pragma once

#include "../bpf/profiler.h"
#include "symbols.h"
// Formats and prints a single stack_event to stdout.
// resolver is used to look up kernel symbol names from stack IDs.
void print_event(const stack_event &event, const SymbolResolver &resolver, int stack_traces_fd);
