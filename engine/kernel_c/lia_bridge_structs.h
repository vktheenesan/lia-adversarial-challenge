#ifndef LIA_BRIDGE_STRUCTS_H
#define LIA_BRIDGE_STRUCTS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// STEP-3 SECURITY INVARIANT
// 
// The Right Brain has ZERO authorization authority.
// It may:
//     interpret
//     propose
//     encode
//     request
// It may NOT:
//     authorize
//     modify policy
//     bypass deterministic rules
//     directly commit financial state
//     directly write trusted ledger state
//
// Only the Left Brain can produce an AUTHORIZED verdict.
// Only the Evidence Layer can produce a COMMITTED state transition.
// ============================================================================

// Exact 45-Byte Packed Binary Transaction Envelope
// Shared between Right-Brain (C++ Proposer) and Left-Brain (eBPF/C Evaluator)
typedef struct __attribute__((packed)) {
    uint8_t  hieroglyph_tag[16]; // Offset  0, len 16: Ideographic Domain Tag (e.g. "SCARAB01________")
    uint32_t sender_id;          // Offset 16, len  4: Hashed / Canonical Sender Account ID
    uint32_t recipient_id;       // Offset 20, len  4: Hashed / Canonical Recipient ID
    uint64_t amount_cents;       // Offset 24, len  8: Smallest currency unit (e.g., cents)
    uint8_t  currency_code[4];   // Offset 32, len  4: ISO 4217 Currency String (e.g., "MYR\0")
    uint8_t  postfix_verb;       // Offset 36, len  1: Tamil SOV Opcode (0x01=TRANSFER, 0x02=HOLD, 0x03=QUARANTINE)
    uint64_t timestamp_ns;       // Offset 37, len  8: Nanosecond Monotonic Timestamp
} lia_ring_payload_t;

// Verbs
#define LIA_VERB_TRANSFER   0x01
#define LIA_VERB_HOLD       0x02
#define LIA_VERB_QUARANTINE 0x03

// Compile-Time ABI Integrity Enforcement
#ifdef __cplusplus
static_assert(sizeof(lia_ring_payload_t) == 45, "ABI Mismatch: lia_ring_payload_t must be exactly 45 bytes");
static_assert(offsetof(lia_ring_payload_t, hieroglyph_tag) == 0,  "ABI Mismatch: hieroglyph_tag offset must be 0");
static_assert(offsetof(lia_ring_payload_t, sender_id)      == 16, "ABI Mismatch: sender_id offset must be 16");
static_assert(offsetof(lia_ring_payload_t, recipient_id)   == 20, "ABI Mismatch: recipient_id offset must be 20");
static_assert(offsetof(lia_ring_payload_t, amount_cents)   == 24, "ABI Mismatch: amount_cents offset must be 24");
static_assert(offsetof(lia_ring_payload_t, currency_code)  == 32, "ABI Mismatch: currency_code offset must be 32");
static_assert(offsetof(lia_ring_payload_t, postfix_verb)   == 36, "ABI Mismatch: postfix_verb offset must be 36");
static_assert(offsetof(lia_ring_payload_t, timestamp_ns)   == 37, "ABI Mismatch: timestamp_ns offset must be 37");
#else
_Static_assert(sizeof(lia_ring_payload_t) == 45, "ABI Mismatch: lia_ring_payload_t must be exactly 45 bytes");
_Static_assert(offsetof(lia_ring_payload_t, hieroglyph_tag) == 0,  "ABI Mismatch: hieroglyph_tag offset must be 0");
_Static_assert(offsetof(lia_ring_payload_t, sender_id)      == 16, "ABI Mismatch: sender_id offset must be 16");
_Static_assert(offsetof(lia_ring_payload_t, recipient_id)   == 20, "ABI Mismatch: recipient_id offset must be 20");
_Static_assert(offsetof(lia_ring_payload_t, amount_cents)   == 24, "ABI Mismatch: amount_cents offset must be 24");
_Static_assert(offsetof(lia_ring_payload_t, currency_code)  == 32, "ABI Mismatch: currency_code offset must be 32");
_Static_assert(offsetof(lia_ring_payload_t, postfix_verb)   == 36, "ABI Mismatch: postfix_verb offset must be 36");
_Static_assert(offsetof(lia_ring_payload_t, timestamp_ns)   == 37, "ABI Mismatch: timestamp_ns offset must be 37");
#endif

#ifdef __cplusplus
}
#endif

#endif // LIA_BRIDGE_STRUCTS_H
