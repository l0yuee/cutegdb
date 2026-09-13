// Exercises common Linux anti-VM / sandbox checks. Prints one line per check and
// a final RESULT line; the machine looks virtual unless every check is "clean".
// Used to test cutegdb's anti-anti-VM plugins (cpuid_spoof, vm_file_cloak,
// vm_syscall_cloak). Build for x86/x86-64 (uses CPUID).
#include <cpuid.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

// CPUID leaf 1, ECX bit 31 is the hypervisor-present bit.
static int cpuid_hv_bit(void) {
    unsigned a, b, c, d;
    __cpuid(1, a, b, c, d);
    return (c >> 31) & 1;
}

// CPUID leaf 0x40000000 returns the hypervisor's vendor id.
static int cpuid_vendor(void) {
    unsigned a, b, c, d;
    __cpuid(0x40000000, a, b, c, d);
    char s[13];
    memcpy(s, &b, 4);
    memcpy(s + 4, &c, 4);
    memcpy(s + 8, &d, 4);
    s[12] = 0;
    const char *vm[] = {"VMware", "KVM", "VBox", "Xen", "TCG", "prl", "Microsoft", 0};
    for (int i = 0; vm[i]; i++)
        if (strstr(s, vm[i])) return 1;
    return 0;
}

static int file_has_token(const char *path, const char **tokens, int whole_file) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[4096];
    int hit = 0;
    while (fgets(line, sizeof line, f)) {
        for (int i = 0; tokens[i]; i++)
            if (strstr(line, tokens[i])) { hit = 1; break; }
        if (hit || !whole_file) break;
    }
    fclose(f);
    return hit;
}

static int dmi_detected(void) {
    const char *vm[] = {"VMware", "VirtualBox", "QEMU", "innotek", "Xen", "Bochs", 0};
    return file_has_token("/sys/class/dmi/id/sys_vendor", vm, 0);
}

static int cpuinfo_detected(void) {
    const char *vm[] = {"hypervisor", 0};
    return file_has_token("/proc/cpuinfo", vm, 1);
}

static int mac_detected(void) {
    FILE *f = fopen("/sys/class/net/eth0/address", "r");
    if (!f) return 0;
    char s[32] = {0};
    if (!fgets(s, sizeof s, f)) s[0] = 0;
    fclose(f);
    const char *vm[] = {"00:0c:29", "00:05:69", "00:1c:14", "00:50:56", "08:00:27", "52:54:00", 0};
    for (int i = 0; vm[i]; i++)
        if (strncmp(s, vm[i], 8) == 0) return 1;
    return 0;
}

static int hostname_detected(void) {
    struct utsname u;
    if (uname(&u)) return 0;
    const char *bad[] = {"kali", "sandbox", "cuckoo", "remnux", "malware", "analysis", 0};
    for (int i = 0; bad[i]; i++)
        if (strstr(u.nodename, bad[i])) return 1;
    return 0;
}

int main(void) {
    int bad = 0;
    printf("CPUID_HV: %s\n", cpuid_hv_bit() ? (bad = 1, "DETECTED") : "clean");
    printf("CPUID_VENDOR: %s\n", cpuid_vendor() ? (bad = 1, "DETECTED") : "clean");
    printf("DMI: %s\n", dmi_detected() ? (bad = 1, "DETECTED") : "clean");
    printf("CPUINFO: %s\n", cpuinfo_detected() ? (bad = 1, "DETECTED") : "clean");
    printf("MAC: %s\n", mac_detected() ? (bad = 1, "DETECTED") : "clean");
    printf("HOSTNAME: %s\n", hostname_detected() ? (bad = 1, "DETECTED") : "clean");
    printf("RESULT: %s\n", bad ? "DETECTED" : "CLEAN");
    fflush(stdout);
    return 0;
}
