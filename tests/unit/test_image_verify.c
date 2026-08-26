// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project
// ISO/IEC 25000 | ISO/IEC 15288:2023

/**
 * @file test_image_verify.c
 * @brief Host tests for image header parse bounds
 */

#include "eos_image.h"
#include "eos_hal.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SIM_FLASH_SIZE  (64 * 1024)
static uint8_t sim_flash[SIM_FLASH_SIZE];

static int sim_flash_read(uint32_t addr, void *buf, size_t len)
{
    if (addr + len > SIM_FLASH_SIZE) return EOS_ERR_FLASH;
    memcpy(buf, &sim_flash[addr], len);
    return EOS_OK;
}

static int sim_flash_write(uint32_t addr, const void *buf, size_t len)
{
    if (addr + len > SIM_FLASH_SIZE) return EOS_ERR_FLASH;
    memcpy(&sim_flash[addr], buf, len);
    return EOS_OK;
}

static int sim_flash_erase(uint32_t addr, size_t len)
{
    if (addr + len > SIM_FLASH_SIZE) return EOS_ERR_FLASH;
    memset(&sim_flash[addr], 0xFF, len);
    return EOS_OK;
}

static uint32_t sim_tick = 0;
static uint32_t sim_get_tick(void) { return sim_tick++; }
static void sim_noop(void) {}
static void sim_noop_u32(uint32_t x) { (void)x; }
static void sim_jump(uint32_t addr) { (void)addr; }
static eos_reset_reason_t sim_reset_reason(void) { return EOS_RESET_POWER_ON; }
static bool sim_recovery_pin(void) { return false; }
static void sim_system_reset(void) {}

static const eos_board_ops_t sim_ops = {
    .flash_base          = 0,
    .flash_size          = SIM_FLASH_SIZE,
    .slot_a_addr         = 0x4000,
    .slot_a_size         = 0x8000,
    .slot_b_addr         = 0xC000,
    .slot_b_size         = 0x8000,
    .recovery_addr       = 0,
    .recovery_size       = 0,
    .bootctl_addr        = 0,
    .bootctl_backup_addr = 0x1000,
    .log_addr            = 0x2000,
    .app_vector_offset   = 0,
    .flash_read          = sim_flash_read,
    .flash_write         = sim_flash_write,
    .flash_erase         = sim_flash_erase,
    .watchdog_init       = sim_noop_u32,
    .watchdog_feed       = sim_noop,
    .get_reset_reason    = sim_reset_reason,
    .system_reset        = sim_system_reset,
    .recovery_pin_asserted = sim_recovery_pin,
    .jump                = sim_jump,
    .uart_init           = NULL,
    .uart_send           = NULL,
    .uart_recv           = NULL,
    .get_tick_ms         = sim_get_tick,
    .disable_interrupts  = sim_noop,
    .enable_interrupts   = sim_noop,
    .deinit_peripherals  = sim_noop,
};

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    static void name(void); \
    static void run_##name(void) { \
        memset(sim_flash, 0xFF, sizeof(sim_flash)); \
        sim_tick = 0; \
        eos_hal_init(&sim_ops); \
        printf("  %-50s ", #name); \
        name(); \
        tests_passed++; \
        printf("[PASS]\n"); \
    } \
    static void name(void)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

static void write_header(uint32_t addr, const eos_image_header_t *hdr)
{
    memcpy(&sim_flash[addr], hdr, sizeof(*hdr));
}

static void fill_valid_header(eos_image_header_t *hdr)
{
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = EOS_IMG_MAGIC;
    hdr->hdr_version = EOS_IMAGE_HDR_VERSION;
    hdr->hdr_size = (uint16_t)sizeof(eos_image_header_t);
    hdr->image_size = 0x1000;
    hdr->load_addr = 0x20000000;
    hdr->entry_addr = 0x20000100;
}

TEST(test_parse_valid_header)
{
    eos_image_header_t hdr, out;
    fill_valid_header(&hdr);
    write_header(0x1000, &hdr);
    ASSERT(eos_image_parse_header(0x1000, &out) == EOS_OK);
    ASSERT(out.entry_addr == 0x20000100);
}

TEST(test_parse_null_out)
{
    ASSERT(eos_image_parse_header(0x1000, NULL) == EOS_ERR_INVALID);
}

TEST(test_parse_bad_magic)
{
    eos_image_header_t hdr, out;
    fill_valid_header(&hdr);
    hdr.magic = 0xDEADBEEF;
    write_header(0x1000, &hdr);
    ASSERT(eos_image_parse_header(0x1000, &out) == EOS_ERR_NO_IMAGE);
}

TEST(test_parse_entry_outside_image)
{
    eos_image_header_t hdr, out;
    fill_valid_header(&hdr);
    hdr.entry_addr = 0x20002000; /* image is [0x20000000, 0x20001000) */
    write_header(0x1000, &hdr);
    ASSERT(eos_image_parse_header(0x1000, &out) == EOS_ERR_INVALID);
}

TEST(test_parse_load_plus_size_overflow)
{
    /* load_addr near UINT32_MAX + image_size wraps the old end-address add. */
    eos_image_header_t hdr, out;
    fill_valid_header(&hdr);
    hdr.load_addr = 0xFFFFF000u;
    hdr.image_size = 0x2000; /* 0xFFFFF000 + 0x2000 wraps */
    hdr.entry_addr = 0xFFFFF100u;
    write_header(0x1000, &hdr);
    ASSERT(eos_image_parse_header(0x1000, &out) == EOS_ERR_INVALID);
}


/* Independent CRC32 (IEEE, reflected, init 0xFFFFFFFF, final XOR) so these
   tests do not simply restate whatever image_verify.c happens to compute. */
static uint32_t ref_crc32(const uint8_t *p, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 1u) ? ((crc >> 1) ^ 0xEDB88320u) : (crc >> 1);
    }
    return ~crc;
}

TEST(test_crc_image_with_matching_crc_verifies)
{
    eos_image_header_t hdr;
    fill_valid_header(&hdr);
    hdr.flags = 0;                      /* no SHA256 flag -> CRC32 path */
    hdr.image_size = 0x200;
    hdr.load_addr = 0;
    hdr.entry_addr = 0;

    uint32_t addr = 0x1000;
    uint32_t payload = addr + hdr.hdr_size;
    for (uint32_t i = 0; i < hdr.image_size; i++)
        sim_flash[payload + i] = (uint8_t)(i * 7u + 3u);

    uint32_t expect = ref_crc32(&sim_flash[payload], hdr.image_size);
    memcpy(hdr.hash, &expect, sizeof(expect));

    ASSERT(eos_image_verify_integrity(&hdr, addr) == EOS_OK);
}

TEST(test_crc_image_with_wrong_crc_is_rejected)
{
    eos_image_header_t hdr;
    fill_valid_header(&hdr);
    hdr.flags = 0;
    hdr.image_size = 0x200;
    hdr.load_addr = 0;
    hdr.entry_addr = 0;

    uint32_t addr = 0x1000;
    uint32_t payload = addr + hdr.hdr_size;
    for (uint32_t i = 0; i < hdr.image_size; i++)
        sim_flash[payload + i] = (uint8_t)i;

    uint32_t wrong = ref_crc32(&sim_flash[payload], hdr.image_size) ^ 0xFFFFu;
    memcpy(hdr.hash, &wrong, sizeof(wrong));

    ASSERT(eos_image_verify_integrity(&hdr, addr) == EOS_ERR_CRC);
}

/*
 * Regression: the CRC32 path used to fail OPEN.
 *
 * eos_crc32() returned 0 when a flash read failed, which is indistinguishable
 * from a region that genuinely hashes to 0. An image whose payload could not be
 * read, with a stored CRC of 0, therefore passed the integrity check — and the
 * stored CRC is part of the unauthenticated header, so it is trivially set.
 *
 * The SHA-256 path has always propagated the read error; this asserts the CRC
 * path now behaves the same way.
 */
TEST(test_crc_unreadable_payload_fails_closed)
{
    eos_image_header_t hdr;
    fill_valid_header(&hdr);
    hdr.flags = 0;
    hdr.load_addr = 0;
    hdr.entry_addr = 0;

    /* Place the image so its payload runs past the end of simulated flash;
       sim_flash_read() then fails partway through. */
    uint32_t addr = SIM_FLASH_SIZE - 0x400;
    hdr.image_size = 0x8000;
    memset(hdr.hash, 0, sizeof(hdr.hash));      /* stored CRC == 0 */

    /* Precondition: the payload really is unreadable. */
    uint8_t probe[4];
    ASSERT(eos_hal_flash_read(addr + hdr.hdr_size + hdr.image_size - 4,
                              probe, sizeof(probe)) != EOS_OK);

    ASSERT(eos_image_verify_integrity(&hdr, addr) != EOS_OK);
}

TEST(test_crc32_checked_reports_flash_failure)
{
    uint32_t crc = 0xA5A5A5A5u;
    ASSERT(eos_crc32_checked(SIM_FLASH_SIZE - 4, 64, &crc) == EOS_ERR_FLASH);
    ASSERT(crc == 0xA5A5A5A5u);   /* untouched on failure */

    ASSERT(eos_crc32_checked(0x1000, 16, NULL) == EOS_ERR_INVALID);

    uint32_t ok = 0;
    ASSERT(eos_crc32_checked(0x1000, 16, &ok) == EOS_OK);
    ASSERT(ok == ref_crc32(&sim_flash[0x1000], 16));
}

TEST(test_zero_length_image_is_rejected)
{
    eos_image_header_t hdr;
    fill_valid_header(&hdr);
    hdr.flags = 0;
    hdr.load_addr = 0;
    hdr.entry_addr = 0;
    hdr.image_size = 0;
    memset(hdr.hash, 0, sizeof(hdr.hash));

    ASSERT(eos_image_verify_integrity(&hdr, 0x1000) == EOS_ERR_INVALID);
}

TEST(test_payload_address_overflow_is_rejected)
{
    eos_image_header_t hdr;
    fill_valid_header(&hdr);
    hdr.flags = 0;
    hdr.load_addr = 0;
    hdr.entry_addr = 0;

    /* addr + hdr_size would wrap past the end of the address space. */
    ASSERT(eos_image_verify_integrity(&hdr, UINT32_MAX - 2u) == EOS_ERR_INVALID);
}

TEST(test_verify_integrity_null_header)
{
    ASSERT(eos_image_verify_integrity(NULL, 0x1000) == EOS_ERR_INVALID);
}

int main(void)
{
    printf("=== eBootloader: Image Header Parse Tests ===\n\n");
    run_test_parse_valid_header();
    run_test_parse_null_out();
    run_test_parse_bad_magic();
    run_test_parse_entry_outside_image();
    run_test_parse_load_plus_size_overflow();
    run_test_crc_image_with_matching_crc_verifies();
    run_test_crc_image_with_wrong_crc_is_rejected();
    run_test_crc_unreadable_payload_fails_closed();
    run_test_crc32_checked_reports_flash_failure();
    run_test_zero_length_image_is_rejected();
    run_test_payload_address_overflow_is_rejected();
    run_test_verify_integrity_null_header();
    tests_run = 12;
    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
