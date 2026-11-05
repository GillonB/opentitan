// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/base/hardened.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "sw/device/silicon_creator/lib/sigverify/mldsa_verify.h"

OTTF_DEFINE_TEST_CONFIG();

// Simple smoke test for ML-DSA-87 data structures and verification flow.
static status_t mldsa_verify_smoke_test(void) {
  // Test public key struct alignment and key ID extraction
  sigverify_mldsa87_public_key_t key = {{0}};
  key.data[0] = 0x12345678;

  // Test public key hash tr = SHAKE256(pk, 64)
  uint32_t tr[kMldsa87TrWords] = {0};
  rom_error_t err = mldsa_compute_tr(&key, tr);
  CHECK(err == kErrorOk);
  CHECK(tr[0] == 0xd1856849);

  // Verify sigverify_mldsa87_key_id_get matches expected tr[0]
  CHECK(sigverify_mldsa87_key_id_get(&key) == 0xd1856849);

  // Test Pure ML-DSA-87 message representative mu = SHAKE256(tr || 0x00 || 0x00 || prefix || msg, 64)
  const char prefix[] = "test_prefix";
  const char msg[] = "test_message";
  uint32_t mu[kMldsa87MuWords] = {0};
  err = mldsa_compute_mu(tr, prefix, sizeof(prefix) - 1, msg, sizeof(msg) - 1,
                         mu);
  CHECK(err == kErrorOk);
  CHECK(mu[0] == 0x375d2bb0);

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
