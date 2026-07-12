#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

// Workload simulator for cpu-profiler development.
// Randomly switches between three workload types to exercise different profiler views.
//
// Usage: sim <speed> <cpu> <kernel> <depth>   (all 0-99)
//   speed  : how fast workloads switch (0=slow, 99=rapid)
//   cpu    : weight/intensity of CAS spinning   → thread activity view
//   kernel : weight/intensity of mutex contention → kernel dictionary view
//   depth  : weight/intensity of deep lock chains → call stack view

static int g_speed  = 50;
static int g_cpu    = 50;
static int g_kernel = 50;
static int g_depth  = 50;

static std::atomic<bool> g_stop{false};

// --- Workload: CAS spinning ---
// Threads hammer a shared atomic with compare_exchange, burning pure user CPU.
// Shows up as high user% in the thread activity view.

static std::atomic<int> g_cas_target{0};

static void cpu_worker() {
    int expected = g_cas_target.load();
    while (!g_stop) {
        g_cas_target.compare_exchange_weak(expected, expected + 1);
        expected = g_cas_target.load();
    }
}

// --- Workload: mutex contention ---
// Threads race for a single mutex and do a small busy-wait inside the critical
// section to make the lock worth fighting over.
// Shows up as futex_wait / schedule in the kernel dictionary view.

static std::mutex g_contended_mutex;

static void kernel_worker() {
    while (!g_stop) {
        std::lock_guard<std::mutex> lock(g_contended_mutex);
        // Burn a little time inside the critical section so others pile up.
        volatile int x = 0;
        for (int i = 0; i < 10000; i++) x += i;
        (void)x;
    }
}

// --- Workload: deep lock chains ---
// Threads sleep on a condition variable, get broadcast-woken, then race for a
// mutex. Produces deep scheduler chains: pthread_cond_wait → futex_wait →
// schedule → __switch_to, visible end-to-end in the call stack view.

static std::mutex              g_chain_mutex;
static std::condition_variable g_chain_cv;
static bool                    g_chain_signal = false;

static void depth_worker() {
    while (!g_stop) {
        std::unique_lock<std::mutex> lock(g_chain_mutex);
        g_chain_cv.wait(lock, [] { return g_chain_signal || g_stop.load(); });
        g_chain_signal = false;
    }
}

static void depth_broadcaster() {
    while (!g_stop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        {
            std::lock_guard<std::mutex> lock(g_chain_mutex);
            g_chain_signal = true;
        }
        g_chain_cv.notify_all();
    }
}

// --- Orchestrator ---

static int param_to_threads(int param) {
    // Scale 0-99 → 1-16 threads
    return 1 + (param * 15) / 99;
}

static int speed_to_ms(int speed) {
    // Scale 0-99 → 10000ms-500ms dwell time per workload
    return 10000 - (speed * 9500) / 99;
}

enum class Workload { CPU, KERNEL, DEPTH };

static Workload pick_workload(std::mt19937 &rng) {
    int total = g_cpu + g_kernel + g_depth;
    if (total == 0) return Workload::CPU;
    std::uniform_int_distribution<int> dist(0, total - 1);
    int roll = dist(rng);
    if (roll < g_cpu)              return Workload::CPU;
    if (roll < g_cpu + g_kernel)   return Workload::KERNEL;
    return Workload::DEPTH;
}

static void run_workload(Workload w, int dwell_ms) {
    std::vector<std::thread> threads;

    if (w == Workload::CPU) {
        int n = param_to_threads(g_cpu);
        std::cout << "[sim] CPU spinning  ×" << n << "  for " << dwell_ms << "ms\n";
        for (int i = 0; i < n; i++)
            threads.emplace_back(cpu_worker);

    } else if (w == Workload::KERNEL) {
        int n = param_to_threads(g_kernel);
        std::cout << "[sim] Mutex contend ×" << n << "  for " << dwell_ms << "ms\n";
        for (int i = 0; i < n; i++)
            threads.emplace_back(kernel_worker);

    } else {
        int n = param_to_threads(g_depth);
        std::cout << "[sim] Lock chains   ×" << n << "  for " << dwell_ms << "ms\n";
        threads.emplace_back(depth_broadcaster);
        for (int i = 0; i < n; i++)
            threads.emplace_back(depth_worker);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(dwell_ms));

    g_stop = true;
    g_chain_cv.notify_all();
    for (auto &t : threads) t.join();
    g_stop = false;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        std::cerr << "usage: sim <speed> <cpu> <kernel> <depth>  (each 0-99)\n";
        return 1;
    }

    g_speed  = std::atoi(argv[1]);
    g_cpu    = std::atoi(argv[2]);
    g_kernel = std::atoi(argv[3]);
    g_depth  = std::atoi(argv[4]);

    std::mt19937 rng(std::random_device{}());

    std::cout << "[sim] speed=" << g_speed << " cpu=" << g_cpu
              << " kernel=" << g_kernel << " depth=" << g_depth << "\n";

    while (true) {
        auto w = pick_workload(rng);
        run_workload(w, speed_to_ms(g_speed));
    }
}
