#pragma once
#include "aggregator.h"

class CallStack : public Aggregator {
public:
    std::string title() const override { return "Call Stacks"; }
    std::string description() const override { return "Kernel call chains as a flame graph; width proportional to CPU time"; }
    ftxui::Element render(const std::vector<resolved_event>& events) const override;
};
