// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_SIGVERIFY_MLDSA_VERIFY_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_SIGVERIFY_MLDSA_VERIFY_H_

#include <stddef.h>
#include <stdint.h>

#include "sw/device/lib/base/hardened.h"
#include "sw/device/lib/base/macros.h"
#include "sw/device/silicon_creator/lib/drivers/hmac.h"
#include "sw/device/silicon_creator/lib/drivers/lifecycle.h"
#include "sw/device/silicon_creator/lib/error.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "sw/device/silicon_creator/lib/sigverify/mldsa_key.h"

/**
 * Computes FIPS 204 Pre-Hash mode message digest mu = SHAKE256(tr || M').
 *
 * @param key Pointer to ML-DSA-87 public key.
 * @param msg_digest Precomputed SHA-384 digest of firmware payload.
 * @param[out] mu 64-byte buffer receiving message representative mu.
 * @return Result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t mldsa_compute_mu_prehash(const sigverify_mldsa87_public_key_t *key,
                                     const hmac_digest_sha384_t *msg_digest,
                                     uint32_t *mu);

/**
 * Starts ML-DSA-87 signature verification on OTBN.
 *
 * @param key Public key.
 * @param sig Signature.
 * @param msg_digest Precomputed SHA-384 message digest.
 * @return Result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t mldsa_verify_start(const sigverify_mldsa87_public_key_t *key,
                               const sigverify_mldsa87_signature_t *sig,
                               const hmac_digest_sha384_t *msg_digest);

/**
 * Finishes ML-DSA-87 signature verification on OTBN.
 *
 * @param sig Signature.
 * @param[out] flash_exec Flash execution token.
 * @return Result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t mldsa_verify_finish(const sigverify_mldsa87_signature_t *sig,
                                uint32_t *flash_exec);

/**
 * Synchronous verification entry point.
 *
 * @param key Public key.
 * @param sig Signature.
 * @param msg_digest Precomputed SHA-384 message digest.
 * @param[out] flash_exec Flash execution token.
 * @return Result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t mldsa_verify(const sigverify_mldsa87_public_key_t *key,
                         const sigverify_mldsa87_signature_t *sig,
                         const hmac_digest_sha384_t *msg_digest,
                         uint32_t *flash_exec);

#ifdef __cplusplus
}
#endif

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_SIGVERIFY_MLDSA_VERIFY_H_
