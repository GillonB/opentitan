// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/lib/sigverify/mldsa_key.h"

uint32_t sigverify_mldsa87_key_id_get(
    const sigverify_mldsa87_public_key_t *key) {
  return key->data[0];
}
