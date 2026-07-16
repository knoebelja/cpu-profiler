// Diagnostic: resolve symbols and DWARF variables for a running process.
// Usage: sudo ./debug_resolve <pid>
#include "symbols.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: debug_resolve <pid>\n");
        return 1;
    }
    int pid = atoi(argv[1]);

    SymbolResolver res;
    res.load_kernel_symbols();
    res.load_process_maps(pid);

    // Print all maps for this process
    printf("=== /proc/%d/maps (code segments only, used for function resolution) ===\n", pid);

    // Test DWARF variable resolution by trying to find g_contended_mutex.
    // First show what all_named_maps sees.
    printf("\n=== Calling resolve_variable_name with a sweep of addresses ===\n");
    printf("(will try 0x0 first to trigger map load, then show what loaded)\n");

    // Trigger the load
    std::string name = res.resolve_variable_name(pid, 0x0);
    printf("resolve_variable_name(pid, 0) = '%s'\n", name.c_str());

    // Now re-read maps manually to show what we have
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (f) {
        printf("\n=== Full /proc/%d/maps ===\n", pid);
        char line[512];
        while (fgets(line, sizeof(line), f))
            fputs(line, stdout);
        fclose(f);
    }

    printf("\n=== Function symbol resolution test ===\n");
    // The sim binary's text segment starts at some ASLR address.
    // Let's try resolving a few addresses near where kernel_worker would be.
    // We don't know the exact address without reading maps, but the test below
    // sweeps through entries visible to resolve_user.

    // Read the text segment start from maps
    f = fopen(maps_path, "r");
    uint64_t text_start = 0, text_file_off = 0;
    char sim_path[256] = {};
    if (f) {
        uint64_t start, end, foff;
        char perms[8], path[256];
        while (fscanf(f, "%lx-%lx %7s %lx %*s %*s %255[^\n]\n",
                      &start, &end, perms, &foff, path) >= 4) {
            if (perms[2] == 'x' && path[0] == '/' &&
                strstr(path, "sim") && !strstr(path, "libsim")) {
                text_start = start;
                text_file_off = foff;
                strncpy(sim_path, path, sizeof(sim_path)-1);
                break;
            }
            path[0] = '\0';
        }
        fclose(f);
    }

    if (text_start) {
        printf("sim text segment: start=0x%lx file_offset=0x%lx path=%s\n",
               text_start, text_file_off, sim_path);
        // kernel_worker in ELF is at 0x27d7 (from nm)
        uint64_t kw_elf_vaddr = 0x27d7;
        uint64_t kw_runtime = text_start - text_file_off + kw_elf_vaddr;
        printf("kernel_worker expected runtime addr: 0x%lx\n", kw_runtime);
        printf("resolve_user(pid, 0x%lx) = '%s'\n",
               kw_runtime, res.resolve_user(pid, kw_runtime).c_str());

        // Also try g_contended_mutex
        // ELF addr = 0xa2a0, runtime = load_bias + 0xa2a0
        // load_bias = start of first mapping with file_offset=0
        // We'll find it from maps
        f = fopen(maps_path, "r");
        uint64_t load_bias = 0;
        if (f) {
            uint64_t start, end, foff;
            char perms[8], path[256];
            while (fscanf(f, "%lx-%lx %7s %lx %*s %*s %255[^\n]\n",
                          &start, &end, perms, &foff, path) >= 4) {
                if (foff == 0 && path[0] == '/' && strstr(path, "sim")) {
                    load_bias = start;
                    break;
                }
                path[0] = '\0';
            }
            fclose(f);
        }
        if (load_bias) {
            printf("\nload_bias for sim: 0x%lx\n", load_bias);
            uint64_t mutex_elf = 0xa2a0;
            uint64_t mutex_runtime = load_bias + mutex_elf;
            printf("g_contended_mutex expected runtime addr: 0x%lx\n", mutex_runtime);
            printf("resolve_variable_name(pid, 0x%lx) = '%s'\n",
                   mutex_runtime, res.resolve_variable_name(pid, mutex_runtime).c_str());
        }
    } else {
        printf("Could not find sim text segment in maps\n");
    }

    return 0;
}
