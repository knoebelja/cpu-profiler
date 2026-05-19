#pragma once

#include <string>
#include <map>
#include <cstdint>
#include <vector>

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

    std::vector<std::string> resolve_kernel_stack(int map_fd, int32_t stack_id) const;

private:
    // Sorted map of address -> symbol name.
    // std::map keeps keys in order, which lets us use upper_bound
    // for nearest-match lookup.
    std::map<uint64_t, std::string> kernel_syms_;
};
