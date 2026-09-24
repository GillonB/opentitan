// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_SIGVERIFY_KEYS_MLDSA_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_SIGVERIFY_KEYS_MLDSA_H_

#include <stdint.h>

#include "sw/device/silicon_creator/lib/drivers/lifecycle.h"
#include "sw/device/silicon_creator/lib/error.h"
#include "sw/device/silicon_creator/lib/sigverify/mldsa_key.h"
#include "sw/device/silicon_creator/rom/sigverify_key_types.h"
#include "sw/device/silicon_creator/rom/sigverify_otp_keys.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

/**
 * Validates and retrieves the ML-DSA-87 pinned key entry matching the key ID
 * and verifies that the provided manifest public key matches the pinned OTP digest.
 *
 * This function:
 * 1. Queries the OTP keys cache for a key entry matching `key_id`.
 * 2. Verifies the key state is `kSigVerifyKeyAuthStateProvisioned`.
 * 3. Verifies that the key type is authorized for the given `lc_state`.
 * 4. Computes the SHA-384 digest of `manifest_key` using hardware HMAC.
 * 5. Compares the computed SHA-384 digest against the pinned 48-byte digest in OTP.
 *
 * @param sigverify_ctx Pointer to OTP keys context loaded into SRAM.
 * @param key_id Key ID (first 32-bit word of key digest or public key).
 * @param manifest_key Pointer to full 2,592-byte ML-DSA-87 public key from manifest.
 * @param lc_state Life cycle state of the device.
 * @param[out] key Pointer receiving the validated pinned key entry in OTP cache.
 * @return Result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t sigverify_mldsa_key_get(
    const sigverify_otp_key_ctx_t *sigverify_ctx, uint32_t key_id,
    const sigverify_mldsa87_public_key_t *manifest_key,
    lifecycle_state_t lc_state, const sigverify_rom_mldsa_key_t **key);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_SIGVERIFY_KEYS_MLDSA_H_
