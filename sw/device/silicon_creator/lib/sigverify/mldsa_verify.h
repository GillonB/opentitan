// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_SIGVERIFY_MLDSA_VERIFY_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_SIGVERIFY_MLDSA_VERIFY_H_

#include <stddef.h>
#include <stdint.h>

#include "sw/device/lib/base/hardened.h"
#include "sw/device/lib/base/macros.h"
#include "sw/device/silicon_creator/lib/drivers/lifecycle.h"
#include "sw/device/silicon_creator/lib/error.h"
#include "sw/device/silicon_creator/lib/sigverify/mldsa87_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Computes FIPS 204 §6.2 Pure mode message representative:
 *   mu = SHAKE256(tr || 0x00 || 0x00 || msg_prefix_1 || msg, 64)
 *
 * @param tr Precomputed 64-byte public key hash tr (16 words).
 * @param msg_prefix_1 Optional prefix 1 for message (can be NULL if len == 0).
 * @param msg_prefix_1_len Length of prefix 1 in bytes.
 * @param msg Optional message buffer (can be NULL if len == 0).
 * @param msg_len Length of message in bytes.
 * @param[out] mu 64-byte (16-word) buffer receiving message representative mu.
 * @return Result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t mldsa_compute_mu(const uint32_t *tr,
                             const void *msg_prefix_1,
                             size_t msg_prefix_1_len,
                             const void *msg,
                             size_t msg_len,
                             uint32_t *mu);

/**
 * Starts ML-DSA-87 signature verification on OTBN.
 *
 * @param key Public key.
 * @param sig Signature.
 * @param mu Precomputed message representative mu (16 words).
 * @return Result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t mldsa_verify_start(const sigverify_mldsa87_key_t *key,
                               const sigverify_mldsa87_signature_t *sig,
                               const uint32_t *mu);

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
 * @param mu Precomputed message representative mu (16 words).
 * @param[out] flash_exec Flash execution token.
 * @return Result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t mldsa_verify(const sigverify_mldsa87_key_t *key,
                         const sigverify_mldsa87_signature_t *sig,
                         const uint32_t *mu,
                         uint32_t *flash_exec);

#ifdef __cplusplus
}
#endif

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_SIGVERIFY_MLDSA_VERIFY_H_
