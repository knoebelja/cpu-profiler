#pragma once

#include "ftxui/dom/elements.hpp"
#include "heartbeat_data.h"
#include <string>
#include <vector>

class Aggregator {
public:
  virtual ~Aggregator() = default;

  virtual ftxui::Element render(const heartbeat_data &data) const = 0;

  virtual std::string title() const = 0;
  virtual std::string description() const = 0;

  // Override to support up/down scroll navigation. Default is no-op.
  virtual void scroll(int delta) {}
  virtual void reset_scroll() {}

  // Override to cycle through filter options (e.g. by binary name). Default is no-op.
  virtual void next_filter() {}

  // Override to cycle through debug-symbol filter (all / symbolized / unsymbolized).
  virtual void next_debug_filter() {}
};
