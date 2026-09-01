// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project
// ISO/IEC 25000 | ISO/IEC/IEEE 15288:2023

/**
 * @file test_secure_boot_policy.c
 * @brief The debug-lock policy must be enforced, not merely attempted
 *
 * cfg.lock_debug asks for SWD/JTAG to be closed before the image runs.
 * eos_secure_boot_lock_debug() writes an OTP fuse to do that, and its result
 * used to be discarded -- so a board whose OTP write failed, or one with no
 * otp_write at all, booted with the debug port open while attestation recorded
 * EOS_SBOOT_OK.
 *
 * Kept separate from tests/unit/test_secure_boot.c (added by #72) so the two
 * do not collide.
 */

#include "eos_secure_boot.h"
#include "eos_hal.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    static void name(void); \
    static void run_##name(void) { \
        printf("  %-54s ", #name); \
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

/* ---- Simulated board: OTP only, with a scriptable write result ---- */

#define OTP_SIZE 0x400
static uint8_t sim_otp[OTP_SIZE];
static int otp_write_rc;
static int otp_write_calls;
static int provide_otp_write;

static int sim_otp_read(uint32_t offset, void *buf, size_t len)
{
    if ((uint64_t)offset + len > OTP_SIZE) return EOS_ERR_INVALID;
    memcpy(buf, sim_otp + offset, len);
    return EOS_OK;
}

static int sim_otp_write(uint32_t offset, const void *buf, size_t len)
{
    otp_write_calls++;
    if (otp_write_rc != EOS_OK) return otp_write_rc;
    if ((uint64_t)offset + len > OTP_SIZE) return EOS_ERR_INVALID;
    memcpy(sim_otp + offset, buf, len);
    return EOS_OK;
}

static eos_board_ops_t sim_ops;

static void reset_fixture(void)
{
    memset(&sim_ops, 0, sizeof(sim_ops));
    memset(sim_otp, 0, sizeof(sim_otp));
    sim_ops.otp_read = sim_otp_read;
    if (provide_otp_write) sim_ops.otp_write = sim_otp_write;
    otp_write_rc = EOS_OK;
    otp_write_calls = 0;
    eos_hal_init(&sim_ops);
}

/* A working eFuse: the lock is written and reported. */
TEST(test_lock_debug_reports_success_when_the_fuse_is_written)
{
    provide_otp_write = 1;
    reset_fixture();

    ASSERT(eos_secure_boot_lock_debug() == EOS_OK);
    ASSERT(otp_write_calls == 1);
}

/* An eFuse write that fails leaves the port open. Saying so is the whole
 * point: the caller asked for it to be closed. */
TEST(test_lock_debug_reports_a_failed_fuse_write)
{
    provide_otp_write = 1;
    reset_fixture();
    otp_write_rc = EOS_ERR_FLASH;

    ASSERT(eos_secure_boot_lock_debug() != EOS_OK);
    ASSERT(otp_write_calls == 1);
}

/* The common case, and the one that used to be silent: a board that provides
 * no otp_write at all. eos_hal_otp_write() returns EOS_ERR_NOT_SUPPORTED, so
 * lock_debug: true was a no-op on every such board. */
TEST(test_lock_debug_reports_a_board_with_no_otp_write)
{
    provide_otp_write = 0;
    reset_fixture();

    ASSERT(eos_secure_boot_lock_debug() != EOS_OK);
    ASSERT(otp_write_calls == 0);
}

int main(void)
{
    printf("=== eBootloader: Secure Boot Debug-Lock Policy Tests ===\n\n");

    run_test_lock_debug_reports_success_when_the_fuse_is_written();
    run_test_lock_debug_reports_a_failed_fuse_write();
    run_test_lock_debug_reports_a_board_with_no_otp_write();

    tests_run = 3;
    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
