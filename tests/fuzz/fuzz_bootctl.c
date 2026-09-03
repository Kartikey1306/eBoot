// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file fuzz_bootctl.c
 * @brief libFuzzer harness for boot control block loading
 *
 * The BCB comes out of flash, so every field in it is untrusted. This stages
 * fuzzer bytes as that flash region and drives eos_bootctl_load(), then the
 * state transitions a boot makes on whatever it managed to parse.
 *
 * This harness previously declared eos_bootctl_parse(), which has never
 * existed in this tree -- eos_bootctl_load() is the real entry point. It
 * compiled, because a declaration costs nothing, and it never linked, because
 * EBLDR_BUILD_FUZZ defaults OFF and no CI job set it.
 */

#include "eos_bootctl.h"
#include "eos_hal.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SIM_FLASH_BASE  0x08000000U
#define SIM_FLASH_SIZE  (8u * 1024u)
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
    if (size < 4) {
        return 0;
    }

    static eos_board_ops_t ops;
    memset(&ops, 0, sizeof ops);
    ops.flash_read  = sim_flash_read;
    ops.flash_write = sim_flash_write;
    ops.flash_erase = sim_flash_erase;
    eos_hal_init(&ops);

    memset(sim_flash, 0xFF, sizeof sim_flash);
    memcpy(sim_flash, data, size < SIM_FLASH_SIZE ? size : SIM_FLASH_SIZE);

    eos_bootctl_t bctl;
    memset(&bctl, 0, sizeof bctl);

    if (eos_bootctl_load(&bctl) != EOS_OK) {
        return 0;
    }

    /* Whatever it accepted, a boot then walks these transitions over it. */
    (void)eos_bootctl_increment_attempts(&bctl);
    (void)eos_bootctl_set_pending(&bctl, EOS_SLOT_B);
    (void)eos_bootctl_clear_pending(&bctl);
    (void)eos_bootctl_reset_attempts(&bctl);
    (void)eos_bootctl_save(&bctl);
    return 0;
}
