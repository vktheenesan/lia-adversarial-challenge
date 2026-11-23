#if defined(__linux__) && __has_include(<linux/bpf.h>) && __has_include(<bpf/bpf_helpers.h>)
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#else
// Portable eBPF / XDP compilation stubs for cross-platform static analysis (macOS / BSD / Host CI)
#include <stdint.h>
#include <stddef.h>

#if defined(__APPLE__)
#define SEC(name) __attribute__((used))
#else
#define SEC(name) __attribute__((section(name), used))
#endif
#define __uint(name, val) int (*name)[val]

enum {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_RINGBUF = 27,
};

enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP = 1,
    XDP_PASS = 2,
    XDP_TX = 3,
    XDP_REDIRECT = 4,
};

struct xdp_md {
    uint32_t data;
    uint32_t data_end;
    uint32_t data_meta;
    uint32_t ingress_ifindex;
    uint32_t rx_queue_index;
    uint32_t egress_ifindex;
};

uint64_t bpf_ktime_get_ns(void);
void *bpf_ringbuf_reserve(void *ringbuf, uint64_t size, uint64_t flags);
void bpf_ringbuf_submit(void *data, uint64_t flags);
#define bpf_printk(fmt, ...) ((void)0)
#endif

#include "lia_bridge_structs.h"
#include "panini_rules.h"

// Linux Kernel eBPF Audit Ring Buffer (Kernel = PRODUCER, Userspace Daemon = CONSUMER)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); // 16 MB ring buffer
} lia_kernel_ringbuf SEC(".maps");

SEC("xdp")
int lia_xdp_hypervisor_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // eBPF Verifier Boundary Check
    lia_ring_payload_t *payload = data;
    if ((void *)(payload + 1) > data_end) {
        return XDP_PASS; // Pass standard non-LIA network packets
    }

    // Pass standard network packets that do not bear LIA sovereign hieroglyphic headers
    int has_lia_tag = (payload->hieroglyph_tag[0] == 'S' && payload->hieroglyph_tag[1] == 'C' && payload->hieroglyph_tag[2] == 'A') ||
                      (payload->hieroglyph_tag[0] == 'A' && payload->hieroglyph_tag[1] == 'N' && payload->hieroglyph_tag[2] == 'K') ||
                      (payload->hieroglyph_tag[0] == 'H' && payload->hieroglyph_tag[1] == 'O' && payload->hieroglyph_tag[2] == 'R');
    if (!has_lia_tag) {
        return XDP_PASS; // Transparently pass all standard Ethernet/IP/UDP network traffic
    }

    // 1. Capture Kernel Monotonic Timestamp inside Kernel Boundary
    uint64_t ktime_start_ns = bpf_ktime_get_ns();

    // 2. Evaluate Pāṇinian Rules in Kernel Space
    int verdict = evaluate_panini_rules(payload, ktime_start_ns);

    uint64_t ktime_end_ns = bpf_ktime_get_ns();
    uint64_t kernel_eval_duration_ns = ktime_end_ns - ktime_start_ns;

    // 3. Emit Audit Event via BPF_MAP_TYPE_RINGBUF to User-Space Daemon
    lia_ring_payload_t *event;
    event = bpf_ringbuf_reserve(&lia_kernel_ringbuf, sizeof(*payload), 0);
    if (event) {
        __builtin_memcpy(event, payload, sizeof(*payload));
        if (verdict != LIA_RULE_PASS) {
            event->postfix_verb = LIA_VERB_QUARANTINE;
        }
        // Embed measured in-kernel evaluation duration into timestamp field for audit
        event->timestamp_ns = kernel_eval_duration_ns;
        bpf_ringbuf_submit(event, 0);
    }

    // 4. Kernel Enforcement Action
    if (verdict != LIA_RULE_PASS) {
        bpf_printk("[LIA-HYPERVISOR] INTERDICTED in kernel (%llu ns). Verdict: %d",
                   kernel_eval_duration_ns, verdict);
        return XDP_DROP; // Drop packet at ring-0 NIC boundary
    }

    return XDP_PASS; // Approved packet
}

char _license[] SEC("license") = "GPL";
