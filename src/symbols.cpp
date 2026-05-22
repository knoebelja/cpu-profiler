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

bool SymbolResolver::load_process_maps(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE *f = fopen(path, "r");
    if (!f) return false;

    std::vector<MapEntry> entries;
    uint64_t start, end, file_offset;
    char perms[8], path_buf[256] = {};

    while (fscanf(f, "%lx-%lx %7s %lx %*s %*s %255[^\n]\n",
           &start, &end, perms, &file_offset, path_buf) >= 4) {
        // Only index executable mappings - those are the ones that contain code
        if (perms[2] == 'x' && path_buf[0] == '/') {
            MapEntry e;
            e.start = start;
            e.end = end;
            e.file_offset = file_offset;
            e.path = path_buf;
            entries.push_back(e);
        }
        path_buf[0] = '\0';
    }

    fclose(f);
    process_maps_[pid] = std::move(entries);
    return true;
}

std::string SymbolResolver::resolve_user(int pid, uint64_t address) const {
    auto it = process_maps_.find(pid);
    if (it == process_maps_.end()) return "<no maps>";

    // Find the mapping that contains this address
    for (const auto &entry : it->second) {
        if (address >= entry.start && address < entry.end) {
         // Compute offset within the file
         uint64_t offset = address - entry.start + entry.file_offset;
         char buf[256];
         snprintf(buf, sizeof(buf), "%s+0x%lx", entry.path.c_str(), offset);
         return buf;
        }
    }

    char buf[32];
    snprintf(buf, sizeof(buf), "0x%lx", address);
    return buf;
}

std::vector<std::string> SymbolResolver::resolve_user_stack(int map_fd, int32_t stack_id, int pid) {
    std::vector<std::string> frames;

    // Negative stack IDs mean BPF couldn't capture the stack. Nothing to resolve.
    if (stack_id < 0) return frames;

    // Look up the array of instruction pointer addresses for this stack ID.
    uint64_t addrs[MAX_STACK_DEPTH] = {};
    if (bpf_map_lookup_elem(map_fd, &stack_id, addrs) != 0)
        return frames;

    // Load this process's memory mappings the first time we see it.
    // process_maps_ is a cache keyed by pids, so we only pay this cost once per process.
    if (process_maps_.count(pid) == 0)
        load_process_maps(pid);

    for (int i = 0; i < MAX_STACK_DEPTH; i++) {
        if (addrs[i] == 0) break;
        frames.push_back(resolve_user(pid, addrs[i]));
    }

    return frames;
}
