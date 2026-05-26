#include "thread_activity.h"
#include "ftxui/dom/elements.hpp"
#include "ftxui/screen/terminal.hpp"
#include <algorithm>
#include <unordered_map>

using namespace ftxui;

ftxui::Element ThreadActivityAggregator::render(
    const std::vector<resolved_event> &events) const {
  // Build per-thread stats from the event snapshot
  std::unordered_map<int, ThreadStats> threads;
  for (const auto &event : events) {
    auto &t = threads[event.cpu];
    if (event.pid == 0) {
      t.idle++;
    } else if (event.kernel_stack_id >= 0) {
      t.kernel++;
    } else {
      t.user++;
    }
  }

  // Sort by CPU number so bars are in a stable order
  std::vector<std::pair<int, ThreadStats>> sorted(threads.begin(),
                                                  threads.end());
  std::sort(sorted.begin(), sorted.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });

  auto legend = hbox({
      text("  kernel  ") | bgcolor(Color::Yellow),
      text("  "),
      text("  user    ") | bgcolor(Color::Green),
      text("  "),
      text("  idle    ") | bgcolor(Color::Cyan),
  });

  std::vector<Element> rows;
  rows.push_back(legend);
  rows.push_back(separator());

  int bar_width = Terminal::Size().dimx - 8 - 27;

  for (const auto &[t, stats] : sorted) {
    size_t total = stats.kernel + stats.user + stats.idle;
    if (total == 0)
      continue;

    int kw = (stats.kernel * bar_width) / total;
    int uw = (stats.user * bar_width) / total;
    int iw = bar_width - kw - uw;

    auto bar = hbox({
        text(std::string(kw, ' ')) | bgcolor(Color::Yellow),
        text(std::string(uw, ' ')) | bgcolor(Color::Green),
        text(std::string(iw, ' ')) | bgcolor(Color::Cyan),
    });

    auto label = text("CPU " + std::to_string(t)) | size(WIDTH, EQUAL, 8);
    auto counts = text("   kernel:" + std::to_string(stats.kernel) +
                       " user:" + std::to_string(stats.user) +
                       " idle:" + std::to_string(stats.idle));

    rows.push_back(hbox({label, bar, counts}));
  }

  return vbox(rows);
}
