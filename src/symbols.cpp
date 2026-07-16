#include "symbols.h"
#include "perf.h"
#include <algorithm>
#include <bpf/bpf.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cxxabi.h>
#include <dwarf.h>
#include <elfutils/libdw.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

bool SymbolResolver::load_kernel_symbols() {
  FILE *f = fopen("/proc/kallsyms", "r");
  if (!f)
    return false;

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
  if (kernel_syms_.empty())
    return "<no symbols>";

  // upper_bound gives us the first entry strictly greater than address.
  // Going one back gives us the symbol whose start is <= address,
  // which is the function containing this address.
  auto it = kernel_syms_.upper_bound(address);
  if (it == kernel_syms_.begin())
    return "<unknown>";
  --it;

  return it->second;
}

std::vector<std::string>
SymbolResolver::resolve_kernel_stack(int map_fd, int32_t stack_id, int depth) const {
  std::vector<std::string> frames;
  if (stack_id < 0)
    return frames;

  std::vector<uint64_t> addrs(depth, 0);
  if (bpf_map_lookup_elem(map_fd, &stack_id, addrs.data()) != 0)
    return frames;

  for (int i = 0; i < depth; i++) {
    if (addrs[i] == 0)
      break;
    frames.push_back(resolve_kernel(addrs[i]));
  }

  return frames;
}

bool SymbolResolver::load_process_maps(int pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);

  FILE *f = fopen(path, "r");
  if (!f)
    return false;

  std::vector<MapEntry> entries;
  uint64_t start, end, file_offset;
  char perms[8], path_buf[256] = {};

  while (fscanf(f, "%lx-%lx %7s %lx %*s %*s %255[^\n]\n", &start, &end, perms,
                &file_offset, path_buf) >= 4) {
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

bool SymbolResolver::load_all_named_maps(int pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);

  FILE *f = fopen(path, "r");
  if (!f)
    return false;

  std::vector<MapEntry> entries;
  uint64_t start, end, file_offset;
  char perms[8], path_buf[256] = {};

  while (fscanf(f, "%lx-%lx %7s %lx %*s %*s %255[^\n]\n", &start, &end, perms,
                &file_offset, path_buf) >= 4) {
    if (path_buf[0] == '/') {
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
  all_named_maps_[pid] = std::move(entries);
  return true;
}

static std::string demangle(const std::string &name) {
  int status = 0;
  char *demangled = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);
  if (status == 0 && demangled) {
    std::string result(demangled);
    free(demangled);
    return result;
  }
  return name;
}

void SymbolResolver::load_elf_symbols(const std::string &path) const {
  // elf_begin requires a version call before first use.
  elf_version(EV_CURRENT);

  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    elf_syms_[path] = {};
    return;
  }

  Elf *e = elf_begin(fd, ELF_C_READ, nullptr);
  if (!e) {
    close(fd);
    elf_syms_[path] = {};
    return;
  }

  std::vector<std::pair<uint64_t, std::string>> syms;

  Elf_Scn *scn = nullptr;
  while ((scn = elf_nextscn(e, scn)) != nullptr) {
    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);

    // We want both .symtab (full, may be stripped) and .dynsym (always present)
    if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
      continue;

    Elf_Data *data = elf_getdata(scn, nullptr);
    if (!data)
      continue;

    int count = shdr.sh_size / shdr.sh_entsize;
    for (int i = 0; i < count; i++) {
      GElf_Sym sym;
      gelf_getsym(data, i, &sym);

      // Only function symbols with a nonzero address are useful for stack resolution
      if (GELF_ST_TYPE(sym.st_info) != STT_FUNC || sym.st_value == 0)
        continue;

      const char *name = elf_strptr(e, shdr.sh_link, sym.st_name);
      if (name && *name)
        syms.push_back({sym.st_value, name});
    }
  }

  elf_end(e);
  close(fd);

  std::sort(syms.begin(), syms.end());
  elf_syms_[path] = std::move(syms);
}

std::string SymbolResolver::resolve_user(int pid, uint64_t address) const {
  auto it = process_maps_.find(pid);
  if (it == process_maps_.end())
    return "<no maps>";

  // Find the mapping that contains this address
  for (const auto &entry : it->second) {
    if (address >= entry.start && address < entry.end) {
      // ASLR means the library is loaded at a random base each run.
      // The ELF file itself uses its own virtual address space starting at 0.
      // To convert: subtract the mapping's load address, then add the file
      // offset for the segment. This gives the ELF-relative virtual address
      // that matches what's in the symbol table.
      uint64_t elf_vaddr = address - entry.start + entry.file_offset;

      // Lazily load this file's symbol table on first access.
      if (elf_syms_.count(entry.path) == 0)
        load_elf_symbols(entry.path);

      const auto &syms = elf_syms_[entry.path];
      if (!syms.empty()) {
        // Binary search: find the first symbol with address > elf_vaddr,
        // then step back one — that's the function containing this address.
        auto sit = std::upper_bound(syms.begin(), syms.end(),
                                    std::make_pair(elf_vaddr, std::string{}));
        if (sit != syms.begin()) {
          --sit;
          return demangle(sit->second);
        }
      }

      // No symbol found — fall back to filename+offset (not full path)
      const char *slash = strrchr(entry.path.c_str(), '/');
      const char *fname = slash ? slash + 1 : entry.path.c_str();
      char buf[256];
      snprintf(buf, sizeof(buf), "%s+0x%lx", fname, elf_vaddr);
      return buf;
    }
  }

  char buf[32];
  snprintf(buf, sizeof(buf), "0x%lx", address);
  return buf;
}

std::vector<std::string>
SymbolResolver::resolve_user_stack(int map_fd, int32_t stack_id, int pid, int depth) {
  if (stack_id < 0)
    return {};

  // Heap-allocate the buffer sized to match the map's value_size exactly.
  // A stack buffer sized to MAX_STACK_DEPTH would overflow for maps with
  // larger depth (e.g. lock_stack_traces uses LOCK_MAX_STACK_DEPTH = 127).
  std::vector<uint64_t> addrs(depth, 0);
  if (bpf_map_lookup_elem(map_fd, &stack_id, addrs.data()) != 0)
    return {};

  if (process_maps_.count(pid) == 0)
    load_process_maps(pid);

  std::vector<std::string> frames;
  for (int i = 0; i < depth; i++) {
    if (addrs[i] == 0)
      break;
    frames.push_back(resolve_user(pid, addrs[i]));
  }

  return frames;
}

void SymbolResolver::load_dwarf_variables(const std::string &path) const {
  // Mark as attempted so we don't retry on failure.
  auto &cache = dwarf_vars_[path];

  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0)
    return;

  Dwarf *dbg = dwarf_begin(fd, DWARF_C_READ);
  if (!dbg) {
    close(fd);
    return;
  }

  // Walk every compilation unit in .debug_info
  Dwarf_Off cu_off = 0, next_off;
  size_t hdr_size;
  while (dwarf_nextcu(dbg, cu_off, &next_off, &hdr_size, nullptr, nullptr, nullptr) == 0) {
    Dwarf_Die cu_die;
    if (!dwarf_offdie(dbg, cu_off + hdr_size, &cu_die)) {
      cu_off = next_off;
      continue;
    }

    // Walk all DIEs in this CU looking for DW_TAG_variable
    Dwarf_Die die;
    if (dwarf_child(&cu_die, &die) != 0) {
      cu_off = next_off;
      continue;
    }

    do {
      if (dwarf_tag(&die) != DW_TAG_variable)
        continue;

      // Get the variable name
      const char *name = dwarf_diename(&die);
      if (!name)
        continue;

      // Get the location attribute — we only care about DW_OP_addr (global/static)
      Dwarf_Attribute loc_attr;
      if (!dwarf_attr(&die, DW_AT_location, &loc_attr))
        continue;

      Dwarf_Op *ops;
      size_t nops;
      if (dwarf_getlocation(&loc_attr, &ops, &nops) != 0 || nops == 0)
        continue;

      // DW_OP_addr means the variable lives at a fixed address — global or static
      if (ops[0].atom != DW_OP_addr)
        continue;

      uint64_t elf_addr = ops[0].number;
      cache[elf_addr] = name;

    } while (dwarf_siblingof(&die, &die) == 0);

    cu_off = next_off;
  }

  dwarf_end(dbg);
  close(fd);
}

std::string SymbolResolver::resolve_variable_name(int pid, uint64_t uaddr) {
  if (all_named_maps_.count(pid) == 0)
    load_all_named_maps(pid);

  auto it = all_named_maps_.find(pid);
  if (it == all_named_maps_.end())
    return {};

  // The first PT_LOAD segment (file_offset==0) gives the ASLR load bias.
  // Using elf_vaddr = uaddr - load_bias avoids the p_vaddr != p_offset mismatch
  // that breaks the "uaddr - start + file_offset" formula for data segments.
  std::unordered_map<std::string, uint64_t> load_biases;
  for (const auto &e : it->second) {
    if (e.file_offset == 0 && !load_biases.count(e.path))
      load_biases[e.path] = e.start;
  }

  for (const auto &[path, load_bias] : load_biases) {
    if (uaddr < load_bias)
      continue;
    uint64_t elf_vaddr = uaddr - load_bias;

    if (dwarf_vars_.count(path) == 0)
      load_dwarf_variables(path);

    const auto &vars = dwarf_vars_[path];
    auto vit = vars.find(elf_vaddr);
    if (vit != vars.end())
      return vit->second;
  }

  return {};
}
