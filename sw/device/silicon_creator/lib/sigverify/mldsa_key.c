// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/lib/sigverify/mldsa_key.h"
#include "sw/device/silicon_creator/lib/drivers/hmac.h"

uint32_t sigverify_mldsa87_key_id_get(
    const sigverify_mldsa87_public_key_t *key) {
  hmac_digest_t digest;
  hmac_sha256(key->data, kSigverifyMldsa87PublicKeyBytes, &digest);
  return digest.digest[0];
}
