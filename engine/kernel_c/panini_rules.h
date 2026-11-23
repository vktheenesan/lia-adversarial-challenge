#ifndef PANINI_RULES_H
#define PANINI_RULES_H

#include "lia_bridge_structs.h"

#ifdef __cplusplus
extern "C" {
#endif

// Verdict Codes
#define LIA_RULE_PASS                      1
#define LIA_RULE_DROP_CEILING             -1
#define LIA_RULE_DROP_RISK_TIER           -2
#define LIA_RULE_DROP_CURRENCY            -3
#define LIA_RULE_DROP_SENDER_RECIPIENT    -4
#define LIA_RULE_DROP_MALFORMED_HEADER    -5
#define LIA_RULE_DROP_TIMESTAMP_ANOMALY   -6
#define LIA_RULE_DROP_UNKNOWN_VERB        -7
#define LIA_RULE_DROP_OVERFLOW            -8

// Daily velocity limit: RM 50,000.00 = 5,000,000 cents
#define LIA_DAILY_VELOCITY_CEILING_CENTS  5000000ULL

/**
 * Deterministic Paribhāṣā Precedence Evaluator.
 * "Specific Restrictions Override General Permissions".
 * 
 * Returns LIA_RULE_PASS (1) on authorization, or negative error code on rejection.
 */
static inline int validate_hieroglyph_header(const lia_ring_payload_t *payload) {
    if (payload->postfix_verb == LIA_VERB_QUARANTINE) {
        return LIA_RULE_DROP_RISK_TIER;
    }
    if (payload->hieroglyph_tag[0] == 'H' && payload->hieroglyph_tag[1] == 'O' &&
        payload->hieroglyph_tag[2] == 'R' && payload->hieroglyph_tag[3] == 'U' &&
        payload->hieroglyph_tag[4] == 'S') {
        return LIA_RULE_DROP_RISK_TIER;
    }
    int is_scarab = (payload->hieroglyph_tag[0] == 'S' && payload->hieroglyph_tag[1] == 'C' &&
                     payload->hieroglyph_tag[2] == 'A' && payload->hieroglyph_tag[3] == 'R' &&
                     payload->hieroglyph_tag[4] == 'A' && payload->hieroglyph_tag[5] == 'B');
    int is_ankh   = (payload->hieroglyph_tag[0] == 'A' && payload->hieroglyph_tag[1] == 'N' &&
                     payload->hieroglyph_tag[2] == 'K' && payload->hieroglyph_tag[3] == 'H');
    if (!is_scarab && !is_ankh) {
        return LIA_RULE_DROP_MALFORMED_HEADER;
    }
    return LIA_RULE_PASS;
}

static inline int validate_currency_code(const lia_ring_payload_t *payload) {
    if (payload->currency_code[0] == '\0' || payload->currency_code[0] == ' ') {
        return LIA_RULE_DROP_CURRENCY;
    }
    int valid = 0;
    if (payload->currency_code[0] == 'M' && payload->currency_code[1] == 'Y' && payload->currency_code[2] == 'R') valid = 1;
    if (payload->currency_code[0] == 'S' && payload->currency_code[1] == 'G' && payload->currency_code[2] == 'D') valid = 1;
    if (payload->currency_code[0] == 'U' && payload->currency_code[1] == 'S' && payload->currency_code[2] == 'D') valid = 1;
    if (payload->currency_code[0] == 'T' && payload->currency_code[1] == 'H' && payload->currency_code[2] == 'B') valid = 1;
    return valid ? LIA_RULE_PASS : LIA_RULE_DROP_CURRENCY;
}

/**
 * Deterministic Paribhāṣā Precedence Evaluator.
 * "Specific Restrictions Override General Permissions".
 * 
 * Returns LIA_RULE_PASS (1) on authorization, or negative error code on rejection.
 */
static inline int evaluate_panini_rules(const lia_ring_payload_t *payload, uint64_t current_time_ns) {
    if (!payload) return -99;

    // Rule 1: Amount Overflow / Sanity Check
    if (payload->amount_cents == 0 || payload->amount_cents > 0x7FFFFFFFFFFFFFFFULL) {
        return LIA_RULE_DROP_OVERFLOW;
    }

    // Rule 2: Hard Daily System Velocity Limit
    if (payload->amount_cents > LIA_DAILY_VELOCITY_CEILING_CENTS) {
        return LIA_RULE_DROP_CEILING;
    }

    // Rule 3: Identity Collision Check (Sender cannot be recipient)
    if (payload->sender_id == payload->recipient_id) {
        return LIA_RULE_DROP_SENDER_RECIPIENT;
    }

    // Rule 4: Valid Verb Check
    if (payload->postfix_verb != LIA_VERB_TRANSFER &&
        payload->postfix_verb != LIA_VERB_HOLD &&
        payload->postfix_verb != LIA_VERB_QUARANTINE) {
        return LIA_RULE_DROP_UNKNOWN_VERB;
    }

    // Rule 5 & 6: Ideogram & Hieroglyphic Header Validation
    int header_verdict = validate_hieroglyph_header(payload);
    if (header_verdict != LIA_RULE_PASS) return header_verdict;

    // Rule 7: Currency Domain Guard
    int curr_verdict = validate_currency_code(payload);
    if (curr_verdict != LIA_RULE_PASS) return curr_verdict;

    // Rule 8: Timestamp Drift & Rollback Check
    if (current_time_ns > 0) {
        int64_t diff_ns = (int64_t)current_time_ns - (int64_t)payload->timestamp_ns;
        if (diff_ns < -60000000000LL || diff_ns > 86400000000000LL) {
            return LIA_RULE_DROP_TIMESTAMP_ANOMALY;
        }
    }

    return LIA_RULE_PASS;
}

#ifdef __cplusplus
}
#endif

#endif // PANINI_RULES_H
