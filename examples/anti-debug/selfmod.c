// Self-checksum anti-debug check: the program reads its own code through
// /proc/self/mem and looks for the 0xCC byte a software breakpoint leaves behind.
// Used to test cutegdb's swbp_cloak plugin.
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

// A function that is never called but is kept and read back as bytes.
__attribute__((used, noinline)) static int marker(int x) {
    return x * 3 + 1;
}

int main(void) {
    volatile int (*keep)(int) = marker; // keep marker and take its runtime address
    uintptr_t addr = (uintptr_t)keep;

    int fd = open("/proc/self/mem", O_RDONLY);
    unsigned char buf[16] = {0};
    int detected = 0;
    if (fd >= 0 && pread(fd, buf, sizeof buf, (off_t)addr) == (ssize_t)sizeof buf)
        for (int i = 0; i < (int)sizeof buf; i++)
            if (buf[i] == 0xCC) detected = 1;
    if (fd >= 0) close(fd);

    printf("SWBP: %s\n", detected ? "DETECTED" : "clean");
    printf("RESULT: %s\n", detected ? "DETECTED" : "CLEAN");
    fflush(stdout);
    return 0;
}
