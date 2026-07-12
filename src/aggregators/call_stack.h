#pragma once
#include "aggregator.h"
#include <atomic>

class CallStack : public Aggregator {
public:
    std::string title() const override { return "Call Stacks"; }
    std::string description() const override { return "Kernel + userspace call chains as a prefix tree; up/down to scroll"; }
    ftxui::Element render(const std::vector<resolved_event>& events) const override;
    void scroll(int delta) override { scroll_offset_ += delta; }
    void reset_scroll() override { scroll_offset_ = 0; }
private:
    mutable std::atomic<int> scroll_offset_{0};
};
