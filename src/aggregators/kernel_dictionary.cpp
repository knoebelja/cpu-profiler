#include "kernel_dictionary.h"
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <ftxui/dom/elements.hpp>
#include <nlohmann/json.hpp>
#include <unordered_set>
#include <vector>

using namespace ftxui;
using json = nlohmann::json;

struct SymbolInfo {
  std::string description;
  std::string category;
};

static Color category_color(const std::string &cat) {
    if (cat == "scheduler")  return Color::Yellow;
    if (cat == "syscall")    return Color::Cyan;
    if (cat == "memory")     return Color::Green;
    if (cat == "network")    return Color::BlueLight;
    if (cat == "filesystem") return Color::Magenta;
    if (cat == "locking")    return Color::Red;
    if (cat == "interrupt")  return Color::YellowLight;
    if (cat == "idle")       return Color::GrayLight;
    if (cat == "drm")        return Color::MagentaLight;
    if (cat == "block-io")   return Color::GreenLight;
    if (cat == "process")    return Color::CyanLight;
    if (cat == "cgroup")     return Color::White;
    if (cat == "tty")        return Color::White;
    if (cat == "wifi")       return Color::BlueLight;
    if (cat == "dma")        return Color::RedLight;
    return Color::Default;
}

static std::unordered_map<std::string, SymbolInfo> load_descriptions() {
  std::unordered_map<std::string, SymbolInfo> map;

  auto try_load = [&](const std::string &path) -> bool {
    std::ifstream f(path);
    if (!f)
      return false;
    try {
      json j = json::parse(f);
      for (const auto &entry : j) {
        std::string sym = entry.at("symbol").get<std::string>();
        map[sym] = {entry.value("description", ""),
                    entry.value("category", "")};
      }
      return !map.empty();
    } catch (...) {
      return false;
    }
  };

  const char *sudo_user = getenv("SUDO_USER");
  std::string home = sudo_user ? std::string("/home/") + sudo_user
                               : (getenv("HOME") ? getenv("HOME") : "");
  if (!home.empty() && try_load(home + "/.cpu-profiler/descriptions.json"))
    return map;

  try_load(std::string(SOURCE_DIR) + "/data/descriptions.json");
  return map;
}

ftxui::Element KernelDictionary::render(const heartbeat_data &data) const {
  auto descriptions = load_descriptions();
  std::unordered_map<std::string, int> counts;
  for (const auto &event : data.events) {
    std::unordered_set<std::string> seen;
    for (const auto &raw : event.kernel_syms) {
      if (raw.empty())
        continue;
      auto dot = raw.find('.');
      std::string sym = (dot != std::string::npos) ? raw.substr(0, dot) : raw;
      if (seen.insert(sym).second) {
        counts[sym]++;
      }
    }
  }

  std::vector<std::pair<std::string, int>> ranked(counts.begin(), counts.end());
  std::sort(ranked.begin(), ranked.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });

  int total = static_cast<int>(data.events.size());

  Elements left_rows;
  left_rows.push_back(hbox({
      text(" # ") | bold,
      text("Symbol                  ") | bold,
      text("Count ") | bold,
      text("CPU%  ") | bold,
  }));
  left_rows.push_back(separator());

  for (int i = 0; i < static_cast<int>(ranked.size()); i++) {
    const auto &[sym, count] = ranked[i];
    float pct = total > 0 ? (count * 100.0f / total) : 0.0f;

    char rank_buf[4];
    snprintf(rank_buf, sizeof(rank_buf), "%2d.", i + 1);
    char pct_buf[8];
    snprintf(pct_buf, sizeof(pct_buf), "%5.1f%%", pct);
    char count_buf[8];
    snprintf(count_buf, sizeof(count_buf), "%5d ", count);

    std::string sym_padded =
        sym.size() > 24 ? sym.substr(0, 23) + "\xe2\x80\xa6" : sym;
    while (sym_padded.size() < 24)
      sym_padded += ' ';

    Color col = Color::Default;
    auto dit = descriptions.find(sym);
    if (dit != descriptions.end())
        col = category_color(dit->second.category);

    left_rows.push_back(hbox({
        text(rank_buf) | dim,
        text(sym_padded) | color(col),
        text(count_buf) | dim,
        text(pct_buf),
    }));
  }

  int display_count = std::min(static_cast<int>(ranked.size()), 20);
  Elements box_rows;
  for (int i = 0; i < display_count; i += 2) {
    auto make_box = [&](const std::pair<std::string, int> &entry) {
      const std::string &sym = entry.first;
      std::string desc = "no description available";
      Color col = Color::Default;
      auto it = descriptions.find(sym);
      if (it != descriptions.end()) {
        if (!it->second.description.empty()) desc = it->second.description;
        col = category_color(it->second.category);
      }

      return window(text(sym) | bold | color(col), paragraph(desc));
    };

    Element right_box =
        (i + 1 < display_count)
            ? hbox({make_box(ranked[i]) | flex, make_box(ranked[i + 1]) | flex})
            : hbox({make_box(ranked[i]) | flex, filler()});

    box_rows.push_back(right_box);
  }

  static const std::vector<std::pair<std::string, Color>> kCategories = {
      {"scheduler", Color::Yellow},    {"syscall",    Color::Cyan},
      {"memory",    Color::Green},     {"network",    Color::BlueLight},
      {"filesystem",Color::Magenta},   {"locking",    Color::Red},
      {"interrupt", Color::YellowLight},{"block-io",  Color::GreenLight},
      {"process",   Color::CyanLight}, {"idle",       Color::GrayLight},
      {"drm",       Color::MagentaLight},{"dma",      Color::RedLight},
  };

  Elements legend_items;
  for (const auto &[label, col] : kCategories) {
      legend_items.push_back(text("● " + label + "  ") | color(col));
  }

  return hbox({
      vbox(left_rows) | border,
      vbox({
          vbox(box_rows) | flex,
          separator(),
          hbox(legend_items) | bold,
      }) | flex | border,
  });
}
