// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/lib/sigverify/mldsa87_key.h"

#include "sw/device/lib/base/hardened.h"
#include "sw/device/silicon_creator/lib/drivers/kmac.h"

const uint8_t kSigverifyMldsa87ImageContext[] = {
    'O', 'T', '-', 'M', 'L', 'D', 'S', 'A', '-', 'I', 'M', 'A', 'G', 'E',
};
const size_t kSigverifyMldsa87ImageContextSize =
    sizeof(kSigverifyMldsa87ImageContext);

OT_WEAK
rom_error_t mldsa_compute_tr(const sigverify_mldsa87_key_t *key,
                             uint32_t *tr) {
  HARDENED_RETURN_IF_ERROR(kmac_shake256_configure());
  HARDENED_RETURN_IF_ERROR(kmac_shake256_start());
  kmac_shake256_absorb_words(key->data, kSigverifyMldsa87PkWords);
  kmac_shake256_squeeze_start();
  return kmac_shake256_squeeze_end(tr, kMldsa87TrWords);
}

uint32_t sigverify_mldsa87_key_id_get(
    const sigverify_mldsa87_key_t *key) {
  uint32_t tr[kMldsa87TrWords];
  if (launder32(mldsa_compute_tr(key, tr)) != kErrorOk) {
    return 0;
  }
  return tr[0];
}
