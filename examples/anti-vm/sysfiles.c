// Anti-VM example: hypervisor detection through system files and syscalls.
//
// Defeated by the `vm_file_cloak` plugin (DMI, /proc/cpuinfo, NIC MAC) and the
// `vm_syscall_cloak` plugin (uname hostname).
//
// Build:  cc -g -O0 -o sysfiles sysfiles.c
// Expect: DETECTED on a typical analysis VM; CLEAN with the plugins enabled.
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

static int file_has_token(const char *path, const char **tokens, int scan_all) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[4096];
    int hit = 0;
    while (fgets(line, sizeof line, f)) {
        for (int i = 0; tokens[i]; i++)
            if (strstr(line, tokens[i])) { hit = 1; break; }
        if (hit || !scan_all) break;
    }
    fclose(f);
    return hit;
}

// DMI/SMBIOS strings name the "board" — a hypervisor on a VM.
static int dmi_detected(const char *path) {
    const char *vm[] = {"VMware", "VirtualBox", "QEMU", "innotek", "Xen", "Bochs", "Parallels", 0};
    return file_has_token(path, vm, 0);
}

// The CPU flags in /proc/cpuinfo carry a "hypervisor" flag inside a guest.
static int cpuinfo_detected(void) {
    const char *vm[] = {"hypervisor", 0};
    return file_has_token("/proc/cpuinfo", vm, 1);
}

// A NIC's MAC OUI often belongs to a hypervisor vendor.
static int mac_detected(void) {
    FILE *f = fopen("/sys/class/net/eth0/address", "r");
    if (!f) return 0;
    char mac[32] = {0};
    if (!fgets(mac, sizeof mac, f)) mac[0] = 0;
    fclose(f);
    const char *vm[] = {"00:0c:29", "00:05:69", "00:1c:14", "00:50:56", "08:00:27", "52:54:00", "00:16:3e", 0};
    for (int i = 0; vm[i]; i++)
        if (strncmp(mac, vm[i], 8) == 0) return 1;
    return 0;
}

// Analysis machines often keep a tell-tale hostname.
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
    printf("DMI_VENDOR: %s\n", dmi_detected("/sys/class/dmi/id/sys_vendor") ? (bad = 1, "DETECTED") : "clean");
    printf("DMI_PRODUCT: %s\n", dmi_detected("/sys/class/dmi/id/product_name") ? (bad = 1, "DETECTED") : "clean");
    printf("CPUINFO: %s\n", cpuinfo_detected() ? (bad = 1, "DETECTED") : "clean");
    printf("MAC: %s\n", mac_detected() ? (bad = 1, "DETECTED") : "clean");
    printf("HOSTNAME: %s\n", hostname_detected() ? (bad = 1, "DETECTED") : "clean");
    printf("RESULT: %s\n", bad ? "DETECTED" : "CLEAN");
    fflush(stdout);
    return 0;
}
