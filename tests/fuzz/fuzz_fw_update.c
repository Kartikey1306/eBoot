// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file fuzz_fw_update.c
 * @brief libFuzzer harness for the firmware update ingest path
 *
 * Drives a fuzzer-chosen byte stream through the real update API in the
 * order a transport would: begin -> write (in varying chunk widths) ->
 * finalize. The chunk widths come from the input too, so a header split
 * across two writes is reachable.
 *
 * This harness previously declared eos_fw_update_init(),
 * eos_fw_update_process_chunk() and eos_fw_update_finalize(void) -- an API
 * that has never existed in this tree. It compiled, because a declaration
 * costs nothing, and it never linked, because EBLDR_BUILD_FUZZ defaults OFF
 * and no CI job set it. Same shape as eos#50's fuzz_devicetree, which
 * declared an eos_dtb_parse() that was equally imaginary.
 */

#include "eos_fw_update.h"
#include "eos_hal.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* A simulated flash large enough for the slot the update targets. */
#define SIM_FLASH_BASE  0x08000000U
#define SIM_FLASH_SIZE  (64u * 1024u)
static uint8_t sim_flash[SIM_FLASH_SIZE];

static int sim_flash_read(uint32_t addr, void *buf, size_t len)
{
    if (addr < SIM_FLASH_BASE) return EOS_ERR_INVALID;
    uint32_t off = addr - SIM_FLASH_BASE;
    if ((uint64_t)off + len > SIM_FLASH_SIZE) return EOS_ERR_INVALID;
    memcpy(buf, sim_flash + off, len);
    return EOS_OK;
}

static int sim_flash_write(uint32_t addr, const void *buf, size_t len)
{
    if (addr < SIM_FLASH_BASE) return EOS_ERR_INVALID;
    uint32_t off = addr - SIM_FLASH_BASE;
    if ((uint64_t)off + len > SIM_FLASH_SIZE) return EOS_ERR_INVALID;
    memcpy(sim_flash + off, buf, len);
    return EOS_OK;
}

static int sim_flash_erase(uint32_t addr, size_t len)
{
    if (addr < SIM_FLASH_BASE) return EOS_ERR_INVALID;
    uint32_t off = addr - SIM_FLASH_BASE;
    if ((uint64_t)off + len > SIM_FLASH_SIZE) return EOS_ERR_INVALID;
    memset(sim_flash + off, 0xFF, len);
    return EOS_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) {
        return 0;
    }

    static eos_board_ops_t ops;
    memset(&ops, 0, sizeof ops);
    ops.flash_read  = sim_flash_read;
    ops.flash_write = sim_flash_write;
    ops.flash_erase = sim_flash_erase;
    eos_hal_init(&ops);
    memset(sim_flash, 0xFF, sizeof sim_flash);

    eos_fw_update_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);

    if (eos_fw_update_begin(&ctx, EOS_SLOT_B) != EOS_OK) {
        return 0;
    }

    /* Chunk widths come from the input, so a header straddling two writes
     * is reachable -- that boundary is where a streaming parser goes wrong. */
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = (size_t)(data[offset] % 64u) + 1u;
        if (offset + chunk > size) {
            chunk = size - offset;
        }
        if (eos_fw_update_write(&ctx, data + offset, chunk) != EOS_OK) {
            break;
        }
        offset += chunk;
    }

    (void)eos_fw_update_finalize(&ctx, EOS_UPGRADE_TEST);
    eos_fw_update_abort(&ctx);
    return 0;
}
