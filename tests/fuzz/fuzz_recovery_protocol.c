// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file fuzz_recovery_protocol.c
 * @brief libFuzzer harness for the recovery-mode write bounds check
 *
 * This harness used to declare and call eos_recovery_parse_packet(), which
 * does not exist anywhere in eBoot -- it was an extern declaration with no
 * definition, so the target compiled and failed at link. It had therefore
 * never been built, and nothing said so: a fuzz target that does not link is
 * silent until something turns the job on.
 *
 * There is no recovery *packet parser* to aim at. include/eos_recovery.h
 * declares two functions, and the one that takes attacker-influenced values
 * is eos_recovery_write_in_range(): the guard deciding whether a recovery
 * write lands inside its slot. It is a pure function of four integers -- no
 * flash, no board -- which makes it an exact fit for a fuzzer.
 */

#include "eos_recovery.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint32_t base, slot_size, offset;
    uint16_t len;

    /* 14 bytes: the four arguments, taken raw so the fuzzer reaches the
     * wrap and overflow cases rather than only plausible-looking ones. */
    if (size < 14) {
        return 0;
    }

    memcpy(&base,      data,      sizeof(base));
    memcpy(&slot_size, data + 4,  sizeof(slot_size));
    memcpy(&offset,    data + 8,  sizeof(offset));
    memcpy(&len,       data + 12, sizeof(len));

    /* The contract is that this never reads or writes anything: it only
     * decides. A crash, or an answer that says a wrapping write is in range,
     * is the bug being hunted. */
    (void)eos_recovery_write_in_range(base, slot_size, offset, len);

    return 0;
}
