#pragma once

#include <string>
#include <map>
#include <cstdint>
#include <vector>
#include <unordered_map>

// Represents one line from /proc/PID/maps
struct MapEntry {
    uint64_t start;
    uint64_t end;
    uint64_t file_offset;
    std::string path;
};

// Resolves kernel instruction pointer addresses to symbol names
// by reading /proc/kallsyms at startup.
class SymbolResolver {
public:
    // Loads /proc/kallsyms into memory. Must be called as root -
    // addresses are hidden (shown as 0) for non-root users.
    bool load_kernel_symbols();
	
    // Returns the symbol name for a kernel address, or a hex string if unknown.
    // Uses nearest-match lookup since sampled addresses may be mid-function.
    std::string resolve_kernel(uint64_t address) const;

    // Looks up a stack ID in the BPF stack_traces map and resolves each
    // instruction pointer address to a kernel symbol name.
    std::vector<std::string> resolve_kernel_stack(int map_fd, int32_t stack_id) const;

    // Reads /proc/PID/maps for the given process and stores its memory mappings.
    // Should be called when a new pid is first seen in a sample.
    bool load_process_maps(int pid);

    // Returns the symbol name for a userspace address in the given process,
    // or a hex string if the mapping or symbol can't be found.
    std::string resolve_user(int pid, uint64_t address) const;
private:
    // Sorted map of address -> symbol name.
    // std::map keeps keys in order, which lets us use upper_bound
    // for nearest-match lookup.
    std::map<uint64_t, std::string> kernel_syms_;

    // Keyed by pid, each entry is a sorted list of mappings for that process
    std::unordered_map<int, std::vector<MapEntry>> process_maps_;
};
