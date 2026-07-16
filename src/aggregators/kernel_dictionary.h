#pragma once

#include "aggregator.h"
#include <string>
#include <unordered_map>

class KernelDictionary : public Aggregator {
public:
  std::string title() const override { return "Kernel Dictionary"; }
  std::string description() const override {
    return "Top kernel symbols by CPU utilization with descriptions";
  }
  ftxui::Element render(const heartbeat_data &data) const override;
};
