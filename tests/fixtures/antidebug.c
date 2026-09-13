// Exercises common Linux anti-debugging checks. Prints one line per check and a
// final RESULT line; a debugger is present unless every check is "clean".
// Used to test cutegdb's anti-anti-debug plugins (ptrace_guard, procfs_cloak).
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

// A self-ptrace fails when the process is already being traced.
static int traceme_detected(void) {
    return ptrace(PTRACE_TRACEME, 0, 0, 0) < 0;
}

// /proc/self/status reports the tracer's pid, or 0 when untraced.
static int tracerpid_detected(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    int pid = 0;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "TracerPid:\t%d", &pid) == 1) break;
    fclose(f);
    return pid != 0;
}

// A debugger is usually the parent process; its name gives it away.
static int parent_detected(void) {
    char path[64], name[64] = {0};
    snprintf(path, sizeof path, "/proc/%d/comm", getppid());
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(name, sizeof name, f)) name[0] = 0;
    fclose(f);
    return strstr(name, "gdb") != NULL || strstr(name, "lldb") != NULL;
}

int main(void) {
    int bad = 0;
    printf("TRACEME: %s\n", traceme_detected() ? (bad = 1, "DETECTED") : "clean");
    printf("TRACERPID: %s\n", tracerpid_detected() ? (bad = 1, "DETECTED") : "clean");
    printf("PARENT: %s\n", parent_detected() ? (bad = 1, "DETECTED") : "clean");
    printf("RESULT: %s\n", bad ? "DETECTED" : "CLEAN");
    fflush(stdout);
    return 0;
}
