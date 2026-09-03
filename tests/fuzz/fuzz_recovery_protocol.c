// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file fuzz_recovery_protocol.c
 * @brief libFuzzer harness for the recovery write-range check
 *
 * eos_recovery_write_in_range() is the bounds decision the UART recovery
 * path makes before writing attacker-supplied bytes into a slot. Every
 * argument here comes from the fuzzer, including the slot geometry, so the
 * wrap cases the function documents -- a zero base or size, a zero length,
 * a write running past the slot, and base + offset overflowing -- are all
 * reachable.
 *
 * This harness previously declared eos_recovery_parse_packet(), which has
 * never existed in this tree. It compiled, because a declaration costs
 * nothing, and it never linked, because EBLDR_BUILD_FUZZ defaults OFF and no
 * CI job set it.
 *
 * eos_recovery_enter() is deliberately not driven: it is a command loop over
 * a real UART that does not return on success, which is not a shape libFuzzer
 * can work with. The range check is the part of recovery that takes untrusted
 * numbers and answers a safety question, so it is the part worth fuzzing.
 */

#include "eos_recovery.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* base(4) + slot_size(4) + offset(4) + len(2) */
    if (size < 14) {
        return 0;
    }

    uint32_t base, slot_size, offset;
    uint16_t len;

    memcpy(&base,      data,      sizeof base);
    memcpy(&slot_size, data + 4,  sizeof slot_size);
    memcpy(&offset,    data + 8,  sizeof offset);
    memcpy(&len,       data + 12, sizeof len);

    int rc = eos_recovery_write_in_range(base, slot_size, offset, len);

    /* The contract: a write it accepts must actually fit. If the function
     * ever says yes to one that does not, that is the bug this harness is
     * looking for, and it is worth an abort rather than a silent pass. */
    if (rc == EOS_OK) {
        if (slot_size == 0 || len == 0) {
            __builtin_trap();
        }
        if ((uint64_t)base + offset + len > (uint64_t)base + slot_size) {
            __builtin_trap();
        }
        if ((uint64_t)base + offset < base) {
            __builtin_trap();
        }
    }
    return 0;
}
