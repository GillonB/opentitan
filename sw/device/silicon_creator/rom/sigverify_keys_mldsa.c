// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/rom/sigverify_keys_mldsa.h"

#include "sw/device/lib/base/hardened.h"
#include "sw/device/lib/base/hardened_memory.h"
#include "sw/device/silicon_creator/lib/drivers/hmac.h"
#include "sw/device/silicon_creator/rom/sigverify_otp_keys.h"

rom_error_t sigverify_mldsa_key_get(
    const sigverify_otp_key_ctx_t *sigverify_ctx, uint32_t key_id,
    const sigverify_mldsa87_public_key_t *manifest_key,
    lifecycle_state_t lc_state, const sigverify_rom_mldsa_key_t **key) {
  *key = NULL;

  const sigverify_rom_key_header_t *rom_key = NULL;
  rom_error_t error = sigverify_otp_keys_get(
      (sigverify_otp_keys_get_params_t){
          .key_id = key_id,
          .lc_state = lc_state,
          .key_array =
              (const sigverify_rom_key_header_t *)(sigverify_ctx->keys.mldsa),
          .key_cnt = kSigVerifyOtpKeysMldsaCount,
          .key_size = sizeof(sigverify_rom_mldsa_key_t),
          .key_states = (uint32_t *)&sigverify_ctx->states.mldsa[0],
      },
      &rom_key);

  if (launder32(error) != kErrorOk) {
    return kErrorSigverifyBadMldsaKey;
  }
  HARDENED_CHECK_EQ(error, kErrorOk);

  const sigverify_rom_mldsa_key_t *cand_key =
      (const sigverify_rom_mldsa_key_t *)rom_key;

  // Compute SHA-384 digest of the public key provided in the manifest.
  hmac_digest_sha384_t act_digest;
  hmac_sha384(manifest_key->data, sizeof(manifest_key->data), &act_digest);

  // Compare actual computed digest with the pinned OTP digest.
  hardened_bool_t eq = hardened_memeq(act_digest.digest,
                                      cand_key->entry.digest.digest,
                                      kHmacDigestSha384NumWords);
  if (launder32(eq) != kHardenedBoolTrue) {
    return kErrorSigverifyBadMldsaKey;
  }
  HARDENED_CHECK_EQ(eq, kHardenedBoolTrue);

  *key = cand_key;
  return kErrorOk;
}
