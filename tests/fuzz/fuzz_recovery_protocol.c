// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file fuzz_recovery_protocol.c
 * @brief libFuzzer harness for the recovery write bounds check.
 *
 * This harness used to declare and call `eos_recovery_parse_packet()`. No such
 * function has ever existed in this repository -- the name appears nowhere
 * outside this file -- so the target has never linked, and a fuzz target that
 * does not link is a coverage claim with nothing behind it.
 *
 * eos_recovery_write_in_range() is the function in this module that actually
 * takes untrusted numbers: it decides whether a recovery write stays inside
 * its slot, and it is the check standing between a malformed recovery command
 * and a write outside the slot. Its four parameters are driven from the input.
 */

#include "eos_recovery.h"
#include "eos_types.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint32_t base, slot_size, offset;
    uint16_t len;

    if (size < 14) return 0;

    memcpy(&base,      data + 0,  4);
    memcpy(&slot_size, data + 4,  4);
    memcpy(&offset,    data + 8,  4);
    memcpy(&len,       data + 12, 2);

    /* The contract is a pure predicate: it must return, and must never accept
     * a write that leaves the slot or wraps. Anything it accepts is asserted
     * against the same arithmetic, in wider types that cannot wrap. */
    if (eos_recovery_write_in_range(base, slot_size, offset, len) == EOS_OK) {
        uint64_t end = (uint64_t)base + (uint64_t)offset + (uint64_t)len;
        if (base == 0 || slot_size == 0 || len == 0 ||
            (uint64_t)offset + (uint64_t)len > (uint64_t)slot_size ||
            end > 0xFFFFFFFFULL) {
            __builtin_trap();   /* accepted a write it had to reject */
        }
    }
    return 0;
}
