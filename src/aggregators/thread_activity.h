#pragma once

#include "aggregator.h"
#include <string>
#include <vector>

struct ThreadStats {
  size_t kernel = 0;
  size_t user = 0;
  size_t idle = 0;
};

class ThreadActivityAggregator : public Aggregator {
public:
  ftxui::Element
  render(const std::vector<resolved_event> &events) const override;

  std::string title() const override { return "Thread Activity"; }

  std::string description() const override {
    return "Per-thread breakdown of kernel, user, and idle CPU time";
  }
};
