#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "buffer.h"
#include "collector.h"
#include "symbols.h"

using json = nlohmann::json;

int main() {
    std::filesystem::path path = std::filesystem::path(SOURCE_DIR) / "data" / "descriptions.json";

    // Load existing entries to preserve descriptions already filled in
    std::map<std::string, json> existing;
    {
        std::ifstream f(path);
        if (f) {
            try {
                json j = json::parse(f);
                for (const auto& entry : j) {
                    std::string sym = entry.at("symbol").get<std::string>();
                    existing[sym] = entry;
                }
            } catch (...) {}
        }
    }

    Buffer buffer;
    Collector collector(99, [&](const stack_event &event) { buffer.push(event); });
    std::thread collector_thread([&]() { collector.start(); });

    fprintf(stderr, "Sampling for 2 minutes...\n");
    std::this_thread::sleep_for(std::chrono::minutes(2));

    // Resolve before stopping — map_fd is invalid after collector teardown
    SymbolResolver resolver;
    resolver.load_kernel_symbols();

    auto raw = buffer.swap_out();
    int map_fd = collector.stack_traces_fd();

    size_t added = 0;
    for (const auto &event : raw) {
        if (event.kernel_stack_id < 0 || map_fd < 0) continue;
        auto syms = resolver.resolve_kernel_stack(map_fd, event.kernel_stack_id);
        for (const auto &raw_sym : syms) {
            if (raw_sym.empty()) continue;
            auto dot = raw_sym.find('.');
            std::string sym = (dot != std::string::npos) ? raw_sym.substr(0, dot) : raw_sym;
            if (existing.find(sym) == existing.end()) {
                existing[sym] = { {"symbol", sym}, {"description", ""}, {"category", ""} };
                added++;
            }
        }
    }

    collector.stop();
    collector_thread.join();

    json out = json::array();
    for (const auto &[sym, entry] : existing)
        out.push_back(entry);

    std::ofstream f(path);
    f << out.dump(2) << "\n";

    fprintf(stderr, "Done. %zu new symbols added (%zu total) -> %s\n",
            added, existing.size(), path.c_str());
    return 0;
}
