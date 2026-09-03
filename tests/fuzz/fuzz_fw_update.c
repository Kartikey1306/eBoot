// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file fuzz_fw_update.c
 * @brief libFuzzer harness for the streaming firmware-update ingest path
 *
 * This harness used to declare and call eos_fw_update_init() and
 * eos_fw_update_process_chunk(). Neither exists: they were extern
 * declarations with no definition anywhere in eBoot, so the target compiled
 * and failed at link, and had therefore never been built. The real API in
 * include/eos_fw_update.h is begin/write/finalize/abort.
 *
 * The path worth fuzzing is the one that consumes attacker-supplied bytes:
 * eos_fw_update_write() accumulates a header across arbitrary chunk
 * boundaries, parses it, then streams the payload to flash. Splitting the
 * input at fuzzer-chosen widths is the point -- a header field that spans a
 * chunk boundary is exactly what a single-buffer test never reaches.
 *
 * Flash is backed by a RAM array here. A backend that failed every write
 * would leave the state machine one branch deep and prove nothing.
 */

#include "eos_fw_update.h"
#include "eos_hal.h"
#include "eos_types.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SIM_FLASH_BASE   0x08000000u
#define SIM_FLASH_SIZE   0x00010000u    /* 64 KiB */
#define SIM_SLOT_A_ADDR  (SIM_FLASH_BASE + 0x1000u)
#define SIM_SLOT_SIZE    0x00004000u    /* 16 KiB */
#define SIM_SLOT_B_ADDR  (SIM_SLOT_A_ADDR + SIM_SLOT_SIZE)

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

static int sim_flash_write(uint32_t addr, const void *buf, size_t len)
{
    if (!buf || !sim_in_range(addr, len)) return EOS_ERR_INVALID;
    memcpy(&sim_flash[addr - SIM_FLASH_BASE], buf, len);
    return EOS_OK;
}

static int sim_flash_erase(uint32_t addr, size_t len)
{
    if (!sim_in_range(addr, len)) return EOS_ERR_INVALID;
    memset(&sim_flash[addr - SIM_FLASH_BASE], 0xFF, len);
    return EOS_OK;
}

static const eos_board_ops_t sim_ops = {
    .flash_base   = SIM_FLASH_BASE,
    .flash_size   = SIM_FLASH_SIZE,
    .slot_a_addr  = SIM_SLOT_A_ADDR,
    .slot_a_size  = SIM_SLOT_SIZE,
    .slot_b_addr  = SIM_SLOT_B_ADDR,
    .slot_b_size  = SIM_SLOT_SIZE,
    .flash_read   = sim_flash_read,
    .flash_write  = sim_flash_write,
    .flash_erase  = sim_flash_erase,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    eos_fw_update_ctx_t ctx;
    size_t offset = 0;
    uint8_t control;

    /* One control byte picks the slot and the finish mode; the rest is the
     * image being streamed in. */
    if (size < 2) {
        return 0;
    }
    control = data[0];
    data += 1;
    size -= 1;

    eos_hal_init(&sim_ops);

    if (eos_fw_update_begin(&ctx, (control & 1) ? EOS_SLOT_B : EOS_SLOT_A) != EOS_OK) {
        return 0;
    }

    /* Chunk widths come from the input itself, so consecutive runs split the
     * same bytes differently and header fields land across boundaries. */
    while (offset < size) {
        size_t remaining = size - offset;
        size_t chunk = (size_t)(data[offset] % 64u) + 1u;
        if (chunk > remaining) {
            chunk = remaining;
        }
        if (eos_fw_update_write(&ctx, data + offset, chunk) != EOS_OK) {
            break;
        }
        offset += chunk;
    }

    if (control & 2) {
        (void)eos_fw_update_finalize(&ctx,
                                     (control & 4) ? EOS_UPGRADE_PERMANENT
                                                   : EOS_UPGRADE_TEST);
    } else {
        eos_fw_update_abort(&ctx);
    }

    return 0;
}
