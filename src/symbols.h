#pragma once

#include "perf.h"
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

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
  // depth must match the map's max_entries value size (in u64 slots).
  std::vector<std::string> resolve_kernel_stack(int map_fd, int32_t stack_id,
                                                int depth = MAX_STACK_DEPTH) const;

  // Reads /proc/PID/maps for the given process and stores its memory mappings.
  // Should be called when a new pid is first seen in a sample.
  bool load_process_maps(int pid);

  // Returns the symbol name for a userspace address in the given process.
  // Converts the raw virtual address to an ELF-relative address via the
  // process's memory map (raw_addr - map_start + map_file_offset), then
  // looks up the nearest symbol in that ELF file's symbol table.
  // Falls back to "file+0xoffset" if the ELF isn't loaded or has no symbols.
  std::string resolve_user(int pid, uint64_t address) const;

  // Looks up a stack ID in the BPF stack_traces map and resolves each
  // address to a userspace symbol using the process memory maps.
  // depth must match the map's max_entries value size (in u64 slots).
  // Loads /proc/PID/maps automatically if this pid hasn't been seen before.
  std::vector<std::string> resolve_user_stack(int map_fd, int32_t stack_id,
                                              int pid,
                                              int depth = MAX_STACK_DEPTH);

private:
  // Sorted map of address -> symbol name.
  // std::map keeps keys in order, which lets us use upper_bound
  // for nearest-match lookup.
  std::map<uint64_t, std::string> kernel_syms_;

  // Keyed by pid, each entry is a sorted list of mappings for that process
  std::unordered_map<int, std::vector<MapEntry>> process_maps_;

  // Parses .symtab and .dynsym from the given ELF file and populates
  // elf_syms_[path]. Called lazily the first time a path is seen.
  void load_elf_symbols(const std::string &path) const;

  // ELF symbol table cache, keyed by file path.
  // Each entry is a sorted list of (elf_virtual_address, name) pairs.
  // We parse .dynsym (always present in shared libs) and .symtab (present in
  // unstripped binaries) once per file, then binary-search for lookups.
  // Shared across all pids — the ELF-relative addresses are file-level, not
  // process-level, so one cache entry covers every process using that lib.
  // mutable because load_elf_symbols populates it lazily from const resolve_user
  mutable std::unordered_map<std::string, std::vector<std::pair<uint64_t, std::string>>> elf_syms_;
};
