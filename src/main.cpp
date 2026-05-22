#include <chrono>
#include <memory>
#include <mutex>
#include <signal.h>
#include <thread>
#include <vector>

#include "aggregators/aggregator.h"
#include "aggregators/thread_activity.h"
#include "buffer.h"
#include "collector.h"

#include "ftxui/component/component.hpp"
#include "ftxui/component/screen_interactive.hpp"
#include "ftxui/dom/elements.hpp"

using namespace ftxui;

static Collector *g_collector = nullptr;

static void handle_signal(int) {
  if (g_collector)
    g_collector->stop();
}

int main() {
  Buffer buffer;

  std::vector<std::unique_ptr<Aggregator>> aggregators;
  aggregators.push_back(std::make_unique<ThreadActivityAggregator>());

  int active = 0;

  Collector collector(99,
                      [&](const stack_event &event) { buffer.push(event); });

  g_collector = &collector;
  signal(SIGINT, handle_signal);

  std::thread collector_thread([&]() { collector.start(); });

  auto screen = ScreenInteractive::Fullscreen();

  Element current_view = text("Loading...");
  std::mutex view_mutex;

  std::thread heartbeat([&]() {
    while (g_collector) {
      std::this_thread::sleep_for(std::chrono::milliseconds(3400));

      auto snapshot = buffer.swap_out();
      auto element = aggregators[active]->render(snapshot);

      {
        std::lock_guard<std::mutex> lock(view_mutex);
        current_view = element;
      }

      screen.PostEvent(Event::Custom);
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
          active =
              (active - 1 + (int)aggregators.size()) % (int)aggregators.size();
          return true;
        }
        if (event == Event::ArrowRight) {
          active = (active + 1) % (int)aggregators.size();
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
