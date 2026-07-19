#pragma once
#include "aggregator.h"
#include <atomic>
#include <mutex>
#include <set>
#include <string>

class LockContention : public Aggregator {
public:
    std::string title() const override { return "Lock Contention"; }
    std::string description() const override {
        return "Futex mutex holder-waiter pairs; up/down to scroll, f to filter by process";
    }
    ftxui::Element render(const heartbeat_data &data) const override;
    void scroll(int delta) override { scroll_offset_ += delta; }
    void reset_scroll() override { scroll_offset_ = 0; }
    void next_filter() override;
    void next_debug_filter() override { debug_filter_++; scroll_offset_ = 0; }
private:
    mutable std::atomic<int> scroll_offset_{0};
    mutable std::atomic<int> debug_filter_{0}; // 0=all, 1=symbolized, 2=unsymbolized

    // Accumulated set of all seen process names — grows monotonically.
    // Active filter stored by name so list shifts don't lose the selection.
    mutable std::mutex seen_mu_;
    mutable std::set<std::string> seen_names_;
    mutable std::string active_filter_name_; // guarded by seen_mu_
};
