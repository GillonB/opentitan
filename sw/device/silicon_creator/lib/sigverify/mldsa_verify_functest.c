// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/base/hardened.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "sw/device/silicon_creator/lib/drivers/hmac.h"
#include "sw/device/silicon_creator/lib/sigverify/mldsa_verify.h"

OTTF_DEFINE_TEST_CONFIG();

// Simple smoke test for ML-DSA-87 data structures and verification flow.
static status_t mldsa_verify_smoke_test(void) {
  // Test public key struct alignment and key ID extraction
  sigverify_mldsa87_public_key_t key = {{0}};
  key.data[0] = 0x12345678;
  CHECK(sigverify_mldsa87_key_id_get(&key) == 0xb58a7510);

  // Test SHA-384 prehash computation
  hmac_digest_sha384_t msg_digest = {{0}};
  msg_digest.digest[0] = 0xdeadbeef;
  uint32_t mu[kMldsa87MuWords] = {0};
  rom_error_t err = mldsa_compute_mu_prehash(&key, &msg_digest, mu);
  CHECK(err == kErrorOk);

  // Check that mu is non-zero after SHAKE-256 absorption
  bool mu_non_zero = false;
  for (size_t i = 0; i < kMldsa87MuWords; ++i) {
    if (mu[i] != 0) {
      mu_non_zero = true;
      break;
    }
  }
  CHECK(mu_non_zero);

  return OK_STATUS();
}

bool test_main(void) {
  status_t result = OK_STATUS();
  EXECUTE_TEST(result, mldsa_verify_smoke_test);
  return status_ok(result);
}
