#include "lock_contention.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <unordered_map>
#include <ftxui/dom/elements.hpp>
#include <nlohmann/json.hpp>

using namespace ftxui;
using json = nlohmann::json;

struct SymInfo { std::string description; std::string category; };

static Color cat_color(const std::string &cat) {
    if (cat == "scheduler")  return Color::Yellow;
    if (cat == "syscall")    return Color::Cyan;
    if (cat == "memory")     return Color::Green;
    if (cat == "network")    return Color::BlueLight;
    if (cat == "filesystem") return Color::Magenta;
    if (cat == "locking")    return Color::Red;
    if (cat == "interrupt")  return Color::YellowLight;
    if (cat == "idle")       return Color::GrayLight;
    if (cat == "process")    return Color::CyanLight;
    return Color::Default;
}

static std::unordered_map<std::string, SymInfo> load_descs() {
    std::unordered_map<std::string, SymInfo> map;
    auto try_load = [&](const std::string &path) {
        std::ifstream f(path);
        if (!f) return;
        try {
            json j = json::parse(f);
            for (const auto &e : j)
                map[e.at("symbol").get<std::string>()] = {
                    e.value("description", ""), e.value("category", "") };
        } catch (...) {}
    };
    const char *sudo_user = getenv("SUDO_USER");
    std::string home = sudo_user ? std::string("/home/") + sudo_user
                                 : (getenv("HOME") ? getenv("HOME") : "");
    if (!home.empty()) try_load(home + "/.cpu-profiler/descriptions.json");
    try_load(std::string(SOURCE_DIR) + "/data/descriptions.json");
    return map;
}

static const int FRAME_MAX = 80;
static const int FRAME_GAP = 8;

static std::string truncate(const std::string &s) {
    if ((int)s.size() <= FRAME_MAX) return s;
    return s.substr(0, FRAME_MAX - 1) + "\xe2\x80\xa6"; // …
}

static Element frame_elem(const std::string &sym,
                           const std::unordered_map<std::string, SymInfo> &descs) {
    std::string s = truncate(sym);
    auto it = descs.find(sym);
    if (it != descs.end())
        return text(s) | bold | color(cat_color(it->second.category));
    return text(s) | dim;
}

// A frame is "real" if it resolved to a function name rather than a raw address
// or file+offset fallback (those always contain '+0x' or start with '0x').
static bool has_real_frame(const std::vector<std::string> &frames) {
    for (const auto &f : frames)
        if (!f.empty() && f.find("+0x") == std::string::npos && f[0] != '0')
            return true;
    return false;
}

// An entry is "symbolized" if it has a named lock AND resolved function frames.
static bool is_symbolized(const resolved_lock_entry &e) {
    return !e.lock_name.empty()
        && (has_real_frame(e.waiter_frames) || has_real_frame(e.holder_frames));
}

void LockContention::next_filter() {
    std::lock_guard<std::mutex> lk(seen_mu_);
    // seen_names_ is a std::set so it's already sorted.
    // Cycle: "" → first name → ... → last name → ""
    if (active_filter_name_.empty()) {
        if (!seen_names_.empty())
            active_filter_name_ = *seen_names_.begin();
    } else {
        auto it = seen_names_.find(active_filter_name_);
        if (it == seen_names_.end() || std::next(it) == seen_names_.end())
            active_filter_name_ = "";
        else
            active_filter_name_ = *std::next(it);
    }
    scroll_offset_ = 0;
}

static std::string fmt_ns(uint64_t ns) {
    char buf[32];
    if (ns < 1000000ULL)
        snprintf(buf, sizeof(buf), "%lluus", (unsigned long long)(ns / 1000));
    else if (ns < 1000000000ULL)
        snprintf(buf, sizeof(buf), "%.1fms", ns / 1e6);
    else
        snprintf(buf, sizeof(buf), "%.2fs", ns / 1e9);
    return buf;
}

// Fixed-width text cell — pads or truncates to exactly `w` characters.
static Element cell(const std::string &s, int w) {
    std::string padded = s.size() >= (size_t)w ? s.substr(0, w) : s + std::string(w - s.size(), ' ');
    return text(padded);
}

ftxui::Element LockContention::render(const heartbeat_data &data) const {
    if (data.lock_stats.empty())
        return text("No lock contention observed") | center;

    auto descs = load_descs();

    // Accumulate new process names into the seen set.
    {
        std::lock_guard<std::mutex> lk(seen_mu_);
        for (const auto &e : data.lock_stats) {
            std::string comm(e.val.comm, strnlen(e.val.comm, 16));
            if (!comm.empty()) seen_names_.insert(comm);
        }
    }

    std::string active_filter;
    {
        std::lock_guard<std::mutex> lk(seen_mu_);
        active_filter = active_filter_name_;
    }

    // Named locks first, then by total wait time descending within each group.
    auto sorted = data.lock_stats;
    std::sort(sorted.begin(), sorted.end(), [](const auto &a, const auto &b) {
        bool an = !a.lock_name.empty(), bn = !b.lock_name.empty();
        if (an != bn) return an > bn;
        return a.val.total_wait_ns > b.val.total_wait_ns;
    });

    if (!active_filter.empty()) {
        sorted.erase(std::remove_if(sorted.begin(), sorted.end(), [&](const auto &e) {
            return std::string(e.val.comm, strnlen(e.val.comm, 16)) != active_filter;
        }), sorted.end());
    }

    static const char *debug_labels[] = { "all", "symbolized", "unsymbolized" };
    int dfilter = debug_filter_.load() % 3;
    debug_filter_ = dfilter;
    if (dfilter == 1) {
        sorted.erase(std::remove_if(sorted.begin(), sorted.end(),
            [](const auto &e) { return !is_symbolized(e); }), sorted.end());
    } else if (dfilter == 2) {
        sorted.erase(std::remove_if(sorted.begin(), sorted.end(),
            [](const auto &e) { return is_symbolized(e); }), sorted.end());
    }

    Elements rows;

    // Filter status line
    rows.push_back(hbox({
        text("  process: ") | dim,
        active_filter.empty() ? (text("all") | dim) : (text(active_filter) | bold | color(Color::Green)),
        text("  symbols: ") | dim,
        dfilter == 0 ? (text("all") | dim)
                     : (text(debug_labels[dfilter]) | bold | color(dfilter == 1 ? Color::Green : Color::Yellow)),
        text("  (f=process  d=symbols)") | dim,
    }));

    // Header — fixed stats columns, LOCK expands to fill remaining space
    rows.push_back(hbox({
        cell("PROCESS",  16) | bold,
        cell("TOTAL",    10) | bold,
        cell("WAITS",    10) | bold,
        cell("AVG",       9) | bold,
        text("LOCK") | bold | flex,
    }));
    rows.push_back(separator());

    for (const auto &entry : sorted) {
        const auto &key = entry.key;
        const auto &val = entry.val;

        char lock_buf[20];
        snprintf(lock_buf, sizeof(lock_buf), "0x%llx", (unsigned long long)key.uaddr);

        // Use DWARF variable name if available, otherwise fall back to hex address
        std::string lock_label = entry.lock_name.empty() ? lock_buf : entry.lock_name;

        uint64_t avg_ns = val.count > 0 ? val.total_wait_ns / val.count : 0;
        std::string threads_str = "\xc3\x97" + std::to_string(val.count); // ×N

        // Summary row — LOCK expands to fill remaining width
        rows.push_back(hbox({
            cell(std::string(val.comm, strnlen(val.comm, 16)), 16),
            cell(fmt_ns(val.total_wait_ns), 10) | color(Color::Red),
            cell(threads_str,  10) | dim,
            cell(fmt_ns(avg_ns), 9) | dim,
            text(lock_label) | (entry.lock_name.empty() ? dim : bold) | flex,
        }));

        // Waiter and holder stacks side by side with tree-branch decoration.
        // Each half gets flex width; ├── for non-last frames, └── for last.
        int nw = (int)entry.waiter_frames.size();
        int nh = (int)entry.holder_frames.size();
        int depth = std::max(nw, nh);

        // UTF-8 box-drawing: ├── \xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80
        //                    └── \xe2\x94\x94\xe2\x94\x80\xe2\x94\x80
        static const char *TEE  = "\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 ";
        static const char *LAST = "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 ";
        static const char *NONE = "     ";

        for (int i = 0; i < depth; i++) {
            bool w_present = i < nw;
            bool h_present = i < nh;
            const char *wb = w_present ? (i == nw - 1 ? LAST : TEE) : NONE;
            const char *hb = h_present ? (i == nh - 1 ? LAST : TEE) : NONE;
            auto welem = w_present ? frame_elem(entry.waiter_frames[i], descs)
                                   : text("");
            auto helem = h_present ? frame_elem(entry.holder_frames[i], descs)
                                   : text("");
            rows.push_back(hbox({
                text(wb) | color(Color::Yellow),
                welem | size(WIDTH, EQUAL, FRAME_MAX),
                text(std::string(FRAME_GAP, ' ')),
                text(hb) | color(Color::Cyan),
                helem | size(WIDTH, EQUAL, FRAME_MAX),
            }));
        }

        rows.push_back(text(""));
    }

    int total = (int)rows.size();
    int offset = std::max(0, std::min(scroll_offset_.load(), total - 1));
    scroll_offset_ = offset;

    Elements visible(rows.begin() + offset, rows.end());
    return vbox(visible) | border;
}
