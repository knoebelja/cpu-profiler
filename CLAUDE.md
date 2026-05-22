# Claude Instructions

## How We're Building This

This project is a hands-on learning exercise for C++ and Linux systems programming. The user writes all the code — Claude's role is to guide, explain, and review.

- **Don't edit files directly** unless explicitly asked (e.g. build system changes, typo fixes the user can't easily track down). Show changes as code blocks with explanations.
- **Be direct and specific.** Exact code to type is fine — the learning comes from understanding it, not writing it from scratch.
- **Always review the user's work before moving on.** Read the file after they've made a change and catch bugs before they compound.
- **Explain the why.** Every change should come with enough context to understand what problem it solves and how it fits the bigger picture.
- **Build system is Claude's responsibility.** The user focuses on BPF and C++; Claude owns CMakeLists.txt and build infrastructure.
- **The user is learning C++.** Explain language features when they appear — but keep it tight, one or two sentences.

## Project State

See README.md for current progress and next steps. The short version:

- TUI is running with a thread activity view (per-CPU kernel/user/idle bar chart)
- Double-buffered event pipeline: collector thread → buffer → 3.4s heartbeat → active aggregator → FTXUI render
- Aggregators are stateless — they take a `vector<stack_event>` snapshot and return an `ftxui::Element`
- Next up: call stack view (nested call tree grouped by pid)

## Architecture

```
Collector (background thread)
  └── pushes stack_event into Buffer

Heartbeat (background thread, every 3.4s)
  └── swaps Buffer
  └── calls active Aggregator::render(snapshot)
  └── posts redraw event to FTXUI screen

FTXUI (main thread)
  └── renders current view with title/description header
  └── left/right arrows switch active aggregator
  └── q to quit
```

## Conventions

- Aggregators live in `src/aggregators/`, inherit from `Aggregator` base class
- Each aggregator is stateless — no member variables, no mutex
- New views = new file in `src/aggregators/`, new `make_unique<>` push in `main.cpp`
- `q` quits, left/right arrow switches views
