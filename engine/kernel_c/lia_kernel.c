#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../include/lia_bridge_structs.h"
#include "../include/panini_rules.h"

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
