#include <signal.h>
#include <cstdio>
#include "collector.h"
#include "aggregator.h"
#include "output.h"
#include "symbols.h"

static Collector *g_collector = nullptr;

static void handle_signal(int) {
    if (g_collector) g_collector->stop();
}

int main() {
    SymbolResolver resolver;
    if (!resolver.load_kernel_symbols()) {
        fprintf(stderr, "Failed to load kernel symbols - are you running as root?\n");
        return 1;
    }
    
    Aggregator aggregator;

    // Wire the collector to the aggregator and output — collector owns sampling,
    // everything else is a consumer of the events it produces.
    Collector collector(99, [&](const stack_event &event) {
        // TODO: make this a --no-idle flag; for now filter idle states by default
        if (event.pid == 0) return;
        aggregator.add(event);
        print_event(event, resolver, collector.stack_traces_fd());
    });

    g_collector = &collector;
    signal(SIGINT, handle_signal);

    printf("Profiling... Ctrl+C to stop.\n");
    collector.start();

    printf("\nTotal samples: %zu\n", aggregator.total());
    return 0;
}
