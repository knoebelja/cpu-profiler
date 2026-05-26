#pragma once

#include "ftxui/dom/elements.hpp"
#include "resolved_event.h"
#include <string>
#include <vector>

class Aggregator {
public:
  virtual ~Aggregator() = default;

  virtual ftxui::Element
  render(const std::vector<resolved_event> &events) const = 0;

  virtual std::string title() const = 0;
  virtual std::string description() const = 0;
};
