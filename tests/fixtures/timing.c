// Timing-based anti-debug checks. A debugger that pauses execution between two
// timestamps inflates the measured delta; here a real sleep stands in for that
// pause. Used to test cutegdb's timing_normalizer plugin (x86/x86-64: rdtsc).
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static inline uint64_t rdtsc(void) {
    unsigned lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

int main(void) {
    int bad = 0;

    uint64_t a = rdtsc();
    usleep(100000); // 100 ms: a stand-in for a debugger pausing between the reads
    uint64_t b = rdtsc();
    printf("RDTSC: %s\n", (b - a) > 10000000ULL ? (bad = 1, "DETECTED") : "clean");

    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    usleep(100000);
    clock_gettime(CLOCK_MONOTONIC, &t2);
    long long ns = (long long)(t2.tv_sec - t1.tv_sec) * 1000000000LL + (t2.tv_nsec - t1.tv_nsec);
    printf("CLOCK: %s\n", ns > 10000000LL ? (bad = 1, "DETECTED") : "clean");

    printf("RESULT: %s\n", bad ? "DETECTED" : "CLEAN");
    fflush(stdout);
    return 0;
}
