// Anti-VM example: CPU-based hypervisor detection through the CPUID instruction.
//
// Defeated by the `cpuid_spoof` plugin, which clears the hypervisor-present bit,
// blanks the hypervisor vendor leaf and scrubs the brand string after each cpuid
// executes.
//
// Build:  cc -g -O0 -o cpuid cpuid.c      (x86 / x86-64 only)
// Expect: DETECTED on a hypervisor guest; CLEAN with cpuid_spoof enabled.
#include <cpuid.h>
#include <stdio.h>
#include <string.h>

// CPUID leaf 1, ECX bit 31 is set by every hypervisor.
static int hypervisor_bit(void) {
    unsigned a, b, c, d;
    __cpuid(1, a, b, c, d);
    return (c >> 31) & 1;
}

// CPUID leaf 0x40000000 returns the hypervisor's 12-byte vendor id.
static int hypervisor_vendor(void) {
    unsigned a, b, c, d;
    __cpuid(0x40000000, a, b, c, d);
    char id[13];
    memcpy(id, &b, 4);
    memcpy(id + 4, &c, 4);
    memcpy(id + 8, &d, 4);
    id[12] = 0;
    const char *vm[] = {"VMware", "KVM", "VBox", "Xen", "TCG", "prl", "Microsoft", 0};
    for (int i = 0; vm[i]; i++)
        if (strstr(id, vm[i])) return 1;
    return 0;
}

// CPUID leaves 0x80000002..0x80000004 hold the 48-byte processor brand string.
// Emulated CPUs advertise the hypervisor here, e.g. "QEMU Virtual CPU version…".
static int hypervisor_brand(void) {
    unsigned r[12];
    __cpuid(0x80000002, r[0], r[1], r[2], r[3]);
    __cpuid(0x80000003, r[4], r[5], r[6], r[7]);
    __cpuid(0x80000004, r[8], r[9], r[10], r[11]);
    char brand[49];
    memcpy(brand, r, 48);
    brand[48] = 0;
    const char *vm[] = {"QEMU", "KVM", "VMware", "Virtual", "Xen", "Bochs", 0};
    for (int i = 0; vm[i]; i++)
        if (strstr(brand, vm[i])) return 1;
    return 0;
}

int main(void) {
    int bad = 0;
    printf("CPUID_HV: %s\n", hypervisor_bit() ? (bad = 1, "DETECTED") : "clean");
    printf("CPUID_VENDOR: %s\n", hypervisor_vendor() ? (bad = 1, "DETECTED") : "clean");
    printf("CPUID_BRAND: %s\n", hypervisor_brand() ? (bad = 1, "DETECTED") : "clean");
    printf("RESULT: %s\n", bad ? "DETECTED" : "CLEAN");
    fflush(stdout);
    return 0;
}
