// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file fuzz_image_verify.c
 * @brief libFuzzer harness for image header parsing
 *
 * This harness declared the parser as
 *     int eos_image_parse_header(const void *flash_base, size_t flash_len);
 * while the real one in core/image_verify.c is
 *     int eos_image_parse_header(uint32_t addr, eos_image_header_t *out);
 *
 * Those are different functions with the same name. It linked -- C does not
 * check a declaration against a definition in another translation unit -- so
 * nothing failed, and that is what made it worth finding: the harness ran and
 * tested nothing. The fuzzer's pointer arrived as the flash address and its
 * length as the output pointer, and because no board ops were registered the
 * first eos_hal_flash_read() failed and the parser returned EOS_ERR_FLASH two
 * lines in. Every input took that path.
 *
 * Now the input is placed in a RAM-backed flash and the parser is called with
 * a real address and a real output header, so the magic, version, hdr_size
 * and length checks are actually reached.
 */

#include "eos_image.h"
#include "eos_hal.h"
#include "eos_types.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SIM_FLASH_BASE  0x08000000u
#define SIM_FLASH_SIZE  0x00002000u    /* 8 KiB */

static uint8_t sim_flash[SIM_FLASH_SIZE];

static int sim_in_range(uint32_t addr, size_t len)
{
    if (addr < SIM_FLASH_BASE) return 0;
    uint32_t off = addr - SIM_FLASH_BASE;
    if (off > SIM_FLASH_SIZE) return 0;
    if (len > (size_t)(SIM_FLASH_SIZE - off)) return 0;
    return 1;
}

static int sim_flash_read(uint32_t addr, void *buf, size_t len)
{
    if (!buf || !sim_in_range(addr, len)) return EOS_ERR_INVALID;
    memcpy(buf, &sim_flash[addr - SIM_FLASH_BASE], len);
    return EOS_OK;
}

static const eos_board_ops_t sim_ops = {
    .flash_base = SIM_FLASH_BASE,
    .flash_size = SIM_FLASH_SIZE,
    .flash_read = sim_flash_read,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    eos_image_header_t hdr;
    size_t len = size;

    if (size < 4) {
        return 0;
    }
    if (len > SIM_FLASH_SIZE) {
        len = SIM_FLASH_SIZE;
    }

    eos_hal_init(&sim_ops);

    /* 0xFF is what erased flash reads as, so the bytes past the input look
     * like an unwritten slot rather than whatever the previous run left. */
    memset(sim_flash, 0xFF, sizeof(sim_flash));
    memcpy(sim_flash, data, len);

    (void)eos_image_parse_header(SIM_FLASH_BASE, &hdr);

    return 0;
}
