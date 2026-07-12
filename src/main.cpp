#include <chrono>
#include <cstring>
#include <deque>
#include <fstream>
#include <memory>
#include <mutex>
#include <signal.h>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "aggregators/aggregator.h"
#include "aggregators/call_stack.h"
#include "aggregators/kernel_dictionary.h"
#include "aggregators/thread_activity.h"
#include "buffer.h"
#include "perf_collector.h"
#include "resolved_event.h"
#include "symbols.h"

#include "ftxui/component/component.hpp"
#include "ftxui/component/screen_interactive.hpp"
#include "ftxui/dom/elements.hpp"

using namespace ftxui;

static Collector *g_collector = nullptr;

static void dump_snapshot(const std::deque<resolved_event> &window) {
  nlohmann::json j = nlohmann::json::array();
  for (const auto &e : window) {
    j.push_back({
        {"pid", e.pid},
        {"comm", std::string(e.comm)},
        {"timestamp_ms", e.timestamp_ms},
        {"kernel_syms", e.kernel_syms},
        {"user_syms", e.user_syms},
    });
  }
  std::ofstream f(std::string(SOURCE_DIR) + "/data/snapshot.json");
  if (f)
    f << j.dump(2);
}

static void handle_signal(int) {
  if (g_collector)
    g_collector->stop();
}

int main() {
  SymbolResolver resolver;
  resolver.load_kernel_symbols();

  Buffer buffer;

  std::vector<std::unique_ptr<Aggregator>> aggregators;
  aggregators.push_back(std::make_unique<ThreadActivityAggregator>());
  aggregators.push_back(std::make_unique<KernelDictionary>());
  aggregators.push_back(std::make_unique<CallStack>());

  int active = 0;

  Collector collector(99,
                      [&](const stack_event &event) { buffer.push(event); });

  g_collector = &collector;
  signal(SIGINT, handle_signal);

  std::thread collector_thread([&]() { collector.start(); });

  auto screen = ScreenInteractive::Fullscreen();

  Element current_view = text("Loading...");
  std::vector<resolved_event> last_snapshot;
  std::mutex view_mutex;

  // Sliding window of the last 60 seconds of resolved events.
  // Only accessed from the heartbeat thread, so no extra locking needed.
  std::deque<resolved_event> window;

  std::thread heartbeat([&]() {
    while (g_collector) {
      std::this_thread::sleep_for(std::chrono::milliseconds(3400));

      uint64_t now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count();

      auto raw = buffer.swap_out();
      int map_fd = collector.stack_traces_fd();
      for (const auto &event : raw) {
        resolved_event re;
        re.pid = event.pid;
        re.cpu = event.cpu;
        re.kernel_stack_id = event.kernel_stack_id;
        re.user_stack_id = event.user_stack_id;
        re.timestamp_ms = now_ms;
        memcpy(re.comm, event.comm, sizeof(event.comm));
        if (map_fd >= 0 && event.kernel_stack_id >= 0)
          re.kernel_syms =
              resolver.resolve_kernel_stack(map_fd, event.kernel_stack_id);
        if (map_fd >= 0 && event.user_stack_id >= 0)
          re.user_syms =
              resolver.resolve_user_stack(map_fd, event.user_stack_id, event.pid);
        window.push_back(std::move(re));
      }

      // Evict events older than 60 seconds
      while (!window.empty() && now_ms - window.front().timestamp_ms > 60000)
        window.pop_front();

      std::vector<resolved_event> snapshot(window.begin(), window.end());
      auto element = aggregators[active]->render(snapshot);

      {
        std::lock_guard<std::mutex> lock(view_mutex);
        last_snapshot = snapshot;
        current_view = element;
      }

      screen.PostEvent(Event::Custom);
      dump_snapshot(window);
    }
  });

  auto component = CatchEvent(
      Renderer([&] {
        std::lock_guard<std::mutex> lock(view_mutex);
        auto title = text(aggregators[active]->title()) | bold | hcenter;
        auto desc = text(aggregators[active]->description()) | dim | hcenter;
        return vbox({title, desc, separator(), current_view | flex});
      }),
      [&](Event event) {
        if (event == Event::ArrowLeft) {
          active = (active - 1 + (int)aggregators.size()) % (int)aggregators.size();
          aggregators[active]->reset_scroll();
          std::lock_guard<std::mutex> lock(view_mutex);
          current_view = aggregators[active]->render(last_snapshot);
          return true;
        }
        if (event == Event::ArrowRight) {
          active = (active + 1) % (int)aggregators.size();
          aggregators[active]->reset_scroll();
          std::lock_guard<std::mutex> lock(view_mutex);
          current_view = aggregators[active]->render(last_snapshot);
          return true;
        }
        if (event == Event::ArrowUp) {
          aggregators[active]->scroll(-1);
          std::lock_guard<std::mutex> lock(view_mutex);
          current_view = aggregators[active]->render(last_snapshot);
          return true;
        }
        if (event == Event::ArrowDown) {
          aggregators[active]->scroll(1);
          std::lock_guard<std::mutex> lock(view_mutex);
          current_view = aggregators[active]->render(last_snapshot);
          return true;
        }
        if (event == Event::Character('q')) {
          screen.ExitLoopClosure()();
          return true;
        }
        return false;
      });

  screen.Loop(component);

  collector.stop();
  collector_thread.join();
  heartbeat.detach();

  return 0;
}
