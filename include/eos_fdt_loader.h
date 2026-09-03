// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file eos_fdt_loader.h
 * @brief Flattened Device Tree (FDT) loading for eBoot
 */

#ifndef EOS_FDT_LOADER_H
#define EOS_FDT_LOADER_H

#include "eos_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FDT_MAGIC           0xD00DFEEDU
#define FDT_BEGIN_NODE      0x00000001U
#define FDT_END_NODE        0x00000002U
#define FDT_PROP            0x00000003U
#define FDT_END             0x00000009U

typedef struct {
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
} fdt_header_t;

/**
 * Return codes. Every entry point below returns 0 on success and one of these
 * on failure; they are distinct so a caller can tell a programming error from
 * a malformed blob from a buffer that was too small.
 *
 *   -1  a required argument was NULL
 *   -2  the blob does not carry the FDT magic
 *   -3  the blob declares an unsupported version (< 16)
 *   -4  the blob does not fit the destination buffer
 *   -5  no such node or property
 *   -6  the blob is malformed: an offset or length escapes it
 *   -7  the property is larger than the caller's buffer (see below)
 *   -8  the node path is deeper than FDT_MAX_PATH_DEPTH components
 */

/**
 * Validate a blob whose length is known.
 *
 * @param avail  bytes actually readable at @p fdt_blob.
 *
 * Prefer this to eos_fdt_validate(). Every bound inside the header — the
 * struct and string block offsets and sizes — is expressed relative to the
 * header's own totalsize field, which is attacker-controlled. Checking those
 * against each other proves only that the blob is internally consistent; it
 * says nothing about how many bytes are really mapped. Passing the real
 * length is what turns the consistency check into a bounds check.
 */
int eos_fdt_validate_sized(const void *fdt_blob, uint32_t avail);

/**
 * Validate a blob, trusting its own totalsize.
 *
 * The caller warrants that at least totalsize bytes are readable at
 * @p fdt_blob. This cannot be checked from here, which is why
 * eos_fdt_validate_sized() exists; use this only where the blob's extent has
 * already been established by other means.
 */
int eos_fdt_validate(const void *fdt_blob);

int eos_fdt_load(uint32_t flash_addr, void *dest, uint32_t max_size);

/**
 * Read a property, on a blob whose length is known.
 *
 * @param fdt_len  bytes actually readable at @p fdt.
 * @param buf_len  in: capacity of @p buf. out: bytes written on success, or
 *                 the property's full length when -7 is returned, so the
 *                 caller can size a retry.
 *
 * Returns -7 rather than truncating. A boot path reads bootargs through here,
 * and a silently clipped value that reports success loses whatever sat at the
 * end of the string.
 */
int eos_fdt_get_prop_sized(const void *fdt, uint32_t fdt_len,
                           const char *node_path, const char *prop_name,
                           void *buf, uint32_t *buf_len);

/**
 * Read a property, trusting the blob's own totalsize. Same warrant as
 * eos_fdt_validate().
 */
int eos_fdt_get_prop(const void *fdt, const char *node_path,
                      const char *prop_name, void *buf, uint32_t *buf_len);

void eos_fdt_pass_to_kernel(uint32_t dtb_addr);

#ifdef __cplusplus
}
#endif
#endif /* EOS_FDT_LOADER_H */
