#include "lock_contention.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ftxui/dom/elements.hpp>

using namespace ftxui;

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

    // Sort by total wait time descending
    auto sorted = data.lock_stats;
    std::sort(sorted.begin(), sorted.end(), [](const auto &a, const auto &b) {
        return a.val.total_wait_ns > b.val.total_wait_ns;
    });

    Elements rows;

    // Header
    rows.push_back(hbox({
        cell("PROCESS",   16) | bold,
        cell("LOCK",      12) | bold,
        cell("TOTAL",     10) | bold,
        cell("THREADS",   12) | bold,
        cell("AVG",       10) | bold,
    }));
    rows.push_back(separator());

    for (const auto &entry : sorted) {
        const auto &key = entry.key;
        const auto &val = entry.val;

        char lock_buf[16], holder_buf[10];
        snprintf(lock_buf,   sizeof(lock_buf),  "0x%08x", (uint32_t)key.uaddr);
        snprintf(holder_buf, sizeof(holder_buf), "%u",     val.holder_tid);

        uint64_t avg_ns = val.count > 0 ? val.total_wait_ns / val.count : 0;
        std::string threads_str = std::to_string(val.count) + " threads";

        // Summary row
        rows.push_back(hbox({
            cell(std::string(val.comm, strnlen(val.comm, 16)), 16),
            cell(lock_buf,     12) | dim,
            cell(fmt_ns(val.total_wait_ns), 10) | color(Color::Red),
            cell(threads_str,  12) | dim,
            cell(fmt_ns(avg_ns), 10) | dim,
        }));

        // Waiter and holder stacks side by side
        int nw = (int)entry.waiter_frames.size();
        int nh = (int)entry.holder_frames.size();
        int depth = std::min(std::max(nw, nh), 6);

        for (int i = 0; i < depth; i++) {
            std::string wf = (i < nw) ? entry.waiter_frames[i] : "";
            std::string hf = (i < nh) ? entry.holder_frames[i] : "";
            rows.push_back(hbox({
                text("  \xe2\x86\x90 ") | color(Color::Yellow),
                cell(wf, 36) | dim,
                text("  \xe2\x86\x92 ") | color(Color::Cyan),
                cell(hf, 36) | dim,
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
