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

// Returns the call chain for one event, root-first.
// Userspace frames come first (reversed so root is first), then kernel frames
// (also reversed). Swap or filter these to get different view flavors.
static std::vector<std::string> build_chain(const resolved_event& event) {
    std::vector<std::string> chain;
    for (int i = (int)event.user_syms.size() - 1; i >= 0; i--) {
        std::string sym = strip_suffix(event.user_syms[i]);
        if (!sym.empty()) chain.push_back(sym);
    }
    for (int i = (int)event.kernel_syms.size() - 1; i >= 0; i--) {
        std::string sym = strip_suffix(event.kernel_syms[i]);
        if (!sym.empty()) chain.push_back(sym);
    }
    return chain;
}

using DescMap = std::unordered_map<std::string, SymInfo>;

// Prefix tree node. count = total samples that passed through this node.
struct TreeNode {
    int count = 0;
    std::map<std::string, TreeNode> children;
};

static void insert_chain(TreeNode& root, const std::vector<std::string>& chain) {
    TreeNode* node = &root;
    node->count++;
    for (const auto& sym : chain) {
        node = &node->children[sym];
        node->count++;
    }
}

// Renders one node and recurses into children sorted by count descending.
// prefix  : the continuing line characters inherited from parent levels
// is_last : determines ├── vs └── and whether to continue │ below
// min_count: branches below this are pruned
// budget  : max lines left to render
static void render_node(
    Elements& rows,
    const std::string& sym,
    const TreeNode& node,
    const DescMap& descriptions,
    const std::string& prefix,
    bool is_last,
    int min_count,
    int depth,
    int& budget
) {
    if (budget <= 0 || depth > 24) return;

    std::string branch = prefix + (is_last ? "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 " : "\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 ");
    std::string cont   = prefix + (is_last ? "    " : "\xe2\x94\x82   ");

    auto it = descriptions.find(sym);
    Color c = (it != descriptions.end()) ? cat_color(it->second.category) : Color::Default;

    char buf[32];
    snprintf(buf, sizeof(buf), " (%d)", node.count);

    auto sym_elem = text(sym);
    if (it != descriptions.end()) sym_elem = sym_elem | bold | color(c);
    else sym_elem = sym_elem | dim;

    rows.push_back(hbox({text(branch) | dim, sym_elem, text(buf) | dim}));
    budget--;

    // Collect and sort children above the pruning threshold
    std::vector<std::pair<std::string, const TreeNode*>> kids;
    int pruned = 0;
    for (const auto& [s, n] : node.children) {
        if (n.count >= min_count) kids.push_back({s, &n});
        else pruned++;
    }
    std::sort(kids.begin(), kids.end(), [](const auto& a, const auto& b) {
        return a.second->count > b.second->count;
    });

    for (int i = 0; i < (int)kids.size() && budget > 0; i++) {
        bool last = (i == (int)kids.size() - 1) && pruned == 0;
        render_node(rows, kids[i].first, *kids[i].second, descriptions,
                    cont, last, min_count, depth + 1, budget);
    }

    if (pruned > 0 && budget > 0) {
        rows.push_back(text(cont + "… " + std::to_string(pruned) + " more") | dim);
        budget--;
    }
}

ftxui::Element CallStack::render(const heartbeat_data &data) const {
    auto descriptions = load_descs();

    TreeNode root;
    for (const auto& event : data.events) {
        auto chain = build_chain(event);
        if (!chain.empty()) insert_chain(root, chain);
    }

    if (root.children.empty())
        return text("No data yet") | center;

    // Prune branches below 0.25% of total samples, minimum 2
    int min_count = std::max(2, root.count / 400);

    // Sort top-level entries by count
    std::vector<std::pair<std::string, const TreeNode*>> tops;
    for (const auto& [sym, node] : root.children)
        if (node.count >= min_count) tops.push_back({sym, &node});
    std::sort(tops.begin(), tops.end(), [](const auto& a, const auto& b) {
        return a.second->count > b.second->count;
    });

    Elements all_rows;
    int budget = 800;

    for (int i = 0; i < (int)tops.size() && budget > 0; i++) {
        const auto& [sym, node] = tops[i];
        auto it = descriptions.find(sym);
        Color c = (it != descriptions.end()) ? cat_color(it->second.category) : Color::Default;

        char buf[32];
        snprintf(buf, sizeof(buf), " (%d)", node->count);

        auto sym_elem = text(sym);
        if (it != descriptions.end()) sym_elem = sym_elem | bold | color(c);
        else sym_elem = sym_elem | dim;

        all_rows.push_back(hbox({sym_elem, text(buf) | dim}));
        budget--;

        std::vector<std::pair<std::string, const TreeNode*>> kids;
        int pruned = 0;
        for (const auto& [s, n] : node->children) {
            if (n.count >= min_count) kids.push_back({s, &n});
            else pruned++;
        }
        std::sort(kids.begin(), kids.end(), [](const auto& a, const auto& b) {
            return a.second->count > b.second->count;
        });

        for (int j = 0; j < (int)kids.size() && budget > 0; j++) {
            bool last = (j == (int)kids.size() - 1) && pruned == 0;
            render_node(all_rows, kids[j].first, *kids[j].second, descriptions,
                        "", last, min_count, 1, budget);
        }
        if (pruned > 0 && budget > 0) {
            all_rows.push_back(text("… " + std::to_string(pruned) + " more") | dim);
            budget--;
        }

        if (i < (int)tops.size() - 1 && budget > 0) {
            all_rows.push_back(text(""));
            budget--;
        }
    }

    // Clamp and apply scroll offset
    int total = (int)all_rows.size();
    int offset = std::max(0, std::min(scroll_offset_.load(), total - 1));
    scroll_offset_ = offset;

    Elements visible(all_rows.begin() + offset, all_rows.end());
    return vbox(visible) | border;
}
