#pragma once
#include "aggregator.h"
#include <atomic>

class LockContention : public Aggregator {
public:
    std::string title() const override { return "Lock Contention"; }
    std::string description() const override {
        return "Futex holder-waiter pairs sorted by total wait time; up/down to scroll";
    }
    ftxui::Element render(const heartbeat_data &data) const override;
    void scroll(int delta) override { scroll_offset_ += delta; }
    void reset_scroll() override { scroll_offset_ = 0; }
private:
    mutable std::atomic<int> scroll_offset_{0};
};
