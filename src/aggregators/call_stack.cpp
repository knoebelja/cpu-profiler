#include "call_stack.h"
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <ftxui/dom/elements.hpp>
#include <nlohmann/json.hpp>

using namespace ftxui;
using json = nlohmann::json;

struct SymInfo {
    std::string description;
    std::string category;
};

static Color cat_color(const std::string& cat) {
    if (cat == "scheduler")  return Color::Yellow;
    if (cat == "syscall")    return Color::Cyan;
    if (cat == "memory")     return Color::Green;
    if (cat == "network")    return Color::BlueLight;
    if (cat == "filesystem") return Color::Magenta;
    if (cat == "locking")    return Color::Red;
    if (cat == "interrupt")  return Color::YellowLight;
    if (cat == "idle")       return Color::GrayLight;
    if (cat == "drm")        return Color::MagentaLight;
    if (cat == "block-io")   return Color::GreenLight;
    if (cat == "process")    return Color::CyanLight;
    if (cat == "cgroup")     return Color::White;
    if (cat == "tty")        return Color::White;
    if (cat == "wifi")       return Color::BlueLight;
    if (cat == "dma")        return Color::RedLight;
    return Color::Default;
}

static std::unordered_map<std::string, SymInfo> load_descs() {
    std::unordered_map<std::string, SymInfo> map;
    auto try_load = [&](const std::string& path) -> bool {
        std::ifstream f(path);
        if (!f) return false;
        try {
            json j = json::parse(f);
            for (const auto& entry : j) {
                std::string sym = entry.at("symbol").get<std::string>();
                map[sym] = { entry.value("description", ""), entry.value("category", "") };
            }
            return !map.empty();
        } catch (...) { return false; }
    };
    const char* sudo_user = getenv("SUDO_USER");
    std::string home = sudo_user ? std::string("/home/") + sudo_user
                                 : (getenv("HOME") ? getenv("HOME") : "");
    if (!home.empty() && try_load(home + "/.cpu-profiler/descriptions.json"))
        return map;
    try_load(std::string(SOURCE_DIR) + "/data/descriptions.json");
    return map;
}

static std::string strip_suffix(const std::string& raw) {
    auto dot = raw.find('.');
    return (dot != std::string::npos) ? raw.substr(0, dot) : raw;
}

ftxui::Element CallStack::render(const std::vector<resolved_event>& events) const {
    auto descriptions = load_descs();

    // Build unique chain counts (root-first: reverse kernel_syms)
    std::map<std::vector<std::string>, int> chain_counts;
    for (const auto& event : events) {
        if (event.kernel_syms.empty()) continue;
        std::vector<std::string> chain;
        for (int i = (int)event.kernel_syms.size() - 1; i >= 0; i--) {
            std::string sym = strip_suffix(event.kernel_syms[i]);
            if (!sym.empty()) chain.push_back(sym);
        }
        if (!chain.empty()) chain_counts[chain]++;
    }

    if (chain_counts.empty())
        return text("No data yet") | center;

    std::vector<std::pair<std::vector<std::string>, int>> chains(chain_counts.begin(), chain_counts.end());
    std::sort(chains.begin(), chains.end(), [](const auto& a, const auto& b) {
        return a.second > b.second;
    });

    int max_count = chains.front().second;
    const int BAR_WIDTH = 60;
    int display = std::min((int)chains.size(), 20);

    // Render each chain as a proportional colored bar + label
    Elements chain_rows;
    for (int i = 0; i < display; i++) {
        const auto& [chain, count] = chains[i];
        int bar_w = std::max(1, (count * BAR_WIDTH) / max_count);
        int seg_w = std::max(1, bar_w / (int)chain.size());

        // Build bar: one colored segment per function
        Elements bar;
        int used = 0;
        for (int s = 0; s < (int)chain.size() && used < bar_w; s++) {
            int w = (s == (int)chain.size() - 1) ? (bar_w - used) : seg_w;
            w = std::min(w, bar_w - used);
            if (w <= 0) break;

            std::string label = chain[s];
            if ((int)label.size() >= w)
                label = w > 1 ? label.substr(0, w - 1) + "\xe2\x80\xa6" : label.substr(0, 1);
            while ((int)label.size() < w) label += ' ';

            Color bg = Color::Default;
            auto it = descriptions.find(chain[s]);
            if (it != descriptions.end()) bg = cat_color(it->second.category);

            auto cell = text(label) | color(Color::Black);
            if (bg != Color::Default) cell = cell | bgcolor(bg);
            bar.push_back(cell);
            used += w;
        }
        // Pad remaining bar space
        if (used < BAR_WIDTH)
            bar.push_back(text(std::string(BAR_WIDTH - used, ' ')));

        // Leaf symbol description as the chain's "definition"
        const std::string& leaf = chain.back();
        std::string desc;
        auto it = descriptions.find(leaf);
        if (it != descriptions.end() && !it->second.description.empty())
            desc = it->second.description;

        char count_buf[8];
        snprintf(count_buf, sizeof(count_buf), "%4d", count);

        chain_rows.push_back(hbox({
            hbox(bar),
            text(" ") | dim,
            text(count_buf) | dim,
            text("  "),
            text(leaf) | bold | color(it != descriptions.end() ? cat_color(it->second.category) : Color::Default),
            text(desc.empty() ? "" : "  " + desc) | dim,
        }));
    }

    return vbox(chain_rows) | border;
}
