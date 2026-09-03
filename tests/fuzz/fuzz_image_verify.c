// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file fuzz_image_verify.c
 * @brief libFuzzer harness for image header parsing and verification
 *
 * Feeds fuzzer-generated data into the image header parser via a simulated
 * flash-backed buffer, exercising bounds checks, magic-number validation,
 * and field-range assertions.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "eos_image.h"
#include "eos_hal.h"

/* The declaration here used to be
 *     extern int eos_image_parse_header(const void *flash_base, size_t len);
 * while the real one is
 *     int eos_image_parse_header(uint32_t addr, eos_image_header_t *out);
 * Two pointers passed where an address and an out-parameter are expected. C
 * has no overloading, so the symbol matched and this would have linked and
 * run, writing a parsed header through whatever `size` happened to be. The
 * header is included now, so the compiler checks the call instead. */

/**
 * Simulated flash read-back: the fuzzer data is treated as raw flash content
 * starting at offset 0.  This lets the parser exercise its flash-pointer
 * arithmetic on arbitrary byte sequences.
 */
#define SIM_FLASH_BASE  0x08000000U
#define SIM_FLASH_SIZE  (16u * 1024u)
static uint8_t sim_flash[SIM_FLASH_SIZE];

static int sim_flash_read(uint32_t addr, void *buf, size_t len)
{
    if (addr < SIM_FLASH_BASE) return EOS_ERR_INVALID;
    uint32_t off = addr - SIM_FLASH_BASE;
    if ((uint64_t)off + len > SIM_FLASH_SIZE) return EOS_ERR_INVALID;
    memcpy(buf, sim_flash + off, len);
    return EOS_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static eos_board_ops_t ops;
    memset(&ops, 0, sizeof ops);
    ops.flash_read = sim_flash_read;
    eos_hal_init(&ops);

    if (size < 4) {
        return 0;
    }

    /* Stage the fuzzer bytes as flash and parse from an address, which is
     * what the real caller does. */
    memcpy(sim_flash, data, size < SIM_FLASH_SIZE ? size : SIM_FLASH_SIZE);

    eos_image_header_t hdr;
    (void)eos_image_parse_header(SIM_FLASH_BASE, &hdr);

    return 0;
}
