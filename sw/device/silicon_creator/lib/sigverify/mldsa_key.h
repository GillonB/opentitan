// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_SIGVERIFY_MLDSA_KEY_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_SIGVERIFY_MLDSA_KEY_H_

#include <stddef.h>
#include <stdint.h>

#include "sw/device/lib/base/macros.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

enum {
  /** Size of an ML-DSA-87 public key in bytes (32 B rho + 2560 B t1). */
  kSigverifyMldsa87PublicKeyBytes = 2592,
  kSigverifyMldsa87PublicKeyWords =
      kSigverifyMldsa87PublicKeyBytes / sizeof(uint32_t),

  /**
   * Size of an ML-DSA-87 signature in bytes.
   * FIPS 204 defines 4,627 bytes (64 B c_tilde + 4,480 B z + 83 B h).
   * Padded to 4,628 bytes for 32-bit word alignment.
   */
  kSigverifyMldsa87SignatureBytes = 4628,
  kSigverifyMldsa87SignatureWords =
      kSigverifyMldsa87SignatureBytes / sizeof(uint32_t),
  kSigverifyMldsa87RawSignatureBytes = 4627,

  /** Size of c_tilde in bytes and words. */
  kMldsa87CTildeBytes = 64,
  kMldsa87CTildeWords = kMldsa87CTildeBytes / sizeof(uint32_t),

  /** Size of intermediate hash mu and tr in words (64 bytes each). */
  kMldsa87MuWords = 16,
  kMldsa87TrWords = 16,

  /** Multi-bit status token written to DMEM by OTBN mldsa87_verify.s on success. */
  kMldsa87StatusOk = 0x7baf73d2,
  kMldsa87StatusFail = 0xadf1aebd,

  /**
   * Non-trivial constant such that:
   *   kSigverifyEcdsaSuccess ^ kSigverifyMldsaSuccess = kSigverifyFlashExec (0xa26a38f7)
   * With kSigverifyEcdsaSuccess = 0x2f06b4e0, kSigverifyMldsaSuccess = 0x8d6c8c17.
   */
  kSigverifyMldsaSuccess = 0x8d6c8c17,
};

/** ML-DSA-87 Public Key structure (aligned to 32-bit words). */
typedef struct sigverify_mldsa87_public_key {
  uint32_t data[kSigverifyMldsa87PublicKeyWords];
} sigverify_mldsa87_public_key_t;

/** ML-DSA-87 Signature structure (4,628 bytes, 1,157 words). */
typedef struct sigverify_mldsa87_signature {
  uint32_t c_tilde[kMldsa87CTildeWords];
  uint32_t z[4480 / sizeof(uint32_t)];
  uint8_t h[83];
  uint8_t _pad[1];  // Index 4,627: strictly 0x00 padding.
} sigverify_mldsa87_signature_t;

OT_ASSERT_SIZE(sigverify_mldsa87_public_key_t, 2592);
OT_ASSERT_SIZE(sigverify_mldsa87_signature_t, 4628);

/** Get key ID (first 32-bit word of public key). */
OT_WARN_UNUSED_RESULT
uint32_t sigverify_mldsa87_key_id_get(
    const sigverify_mldsa87_public_key_t *key);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_SIGVERIFY_MLDSA_KEY_H_
