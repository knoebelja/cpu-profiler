#include "symbols.h"
#include <cstdio>
#include <cstdint>
#include <bpf/bpf.h>
#include "../bpf/profiler.h"

bool SymbolResolver::load_kernel_symbols() {
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return false;

    uint64_t addr;
    char type, name[256];

    while (fscanf(f, "%lx %c %255s%*[^\n]\n", &addr, &type, name) == 3) {
        // Only index function symbols (T = global, t = static)
        if (type == 'T' || type == 't') {
            kernel_syms_[addr] = name;
        }
    }

    fclose(f);
    return !kernel_syms_.empty();
}

std::string SymbolResolver::resolve_kernel(uint64_t address) const {
    if (kernel_syms_.empty()) return "<no symbols>";

    // upper_bound gives us the first entry strictly greater than address.
    // Going one back gives us the symbol whose start is <= address,
    // which is the function containing this address.
    auto it = kernel_syms_.upper_bound(address);
    if (it == kernel_syms_.begin()) return "<unknown>";
    --it;

    return it->second;
}

std::vector<std::string> SymbolResolver::resolve_kernel_stack(int map_fd, int32_t stack_id) const {
    std::vector<std::string> frames;
    if (stack_id < 0) return frames;

    // Look up the array of instruction pointer addresses for this stack ID.
    uint64_t addrs[MAX_STACK_DEPTH] = {};
    if (bpf_map_lookup_elem(map_fd, &stack_id, addrs) != 0)
        return frames;

    // Resolve each non-zero address to a symbol name.
    for (int i = 0; i < MAX_STACK_DEPTH; i++) {
        if (addrs[i] == 0) break;
        frames.push_back(resolve_kernel(addrs[i]));
    }

    return frames;

}
