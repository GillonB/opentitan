// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/rom/sigverify_keys_mldsa.h"

#include <cstring>

#include "gtest/gtest.h"
#include "sw/device/lib/base/hardened.h"
#include "sw/device/silicon_creator/lib/drivers/mock_hmac.h"
#include "sw/device/silicon_creator/lib/error.h"
#include "sw/device/silicon_creator/rom/mock_sigverify_otp_keys.h"
#include "sw/device/silicon_creator/testing/rom_test.h"

namespace sigverify_keys_mldsa_unittest {
namespace {
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

class SigverifyKeysMldsaTest : public rom_test::RomTest {
 protected:
  rom_test::MockHmac hmac_;
  rom_test::MockSigverifyOtpKeys otp_keys_;
};

TEST_F(SigverifyKeysMldsaTest, Success) {
  sigverify_otp_key_ctx_t ctx;
  sigverify_mldsa87_public_key_t manifest_key;
  std::memset(&manifest_key, 0x5a, sizeof(manifest_key));

  sigverify_rom_mldsa_key_t mock_otp_key;
  mock_otp_key.entry.key_type = kSigverifyKeyTypeProd;
  // Set mock digest in OTP
  for (size_t i = 0; i < kHmacDigestSha384NumWords; ++i) {
    mock_otp_key.entry.digest.digest[i] = 0x12340000 + i;
  }
  uint32_t key_id = mock_otp_key.entry.digest.digest[0];

  const sigverify_rom_key_header_t *rom_key_hdr = &mock_otp_key.key_header;
  EXPECT_CALL(otp_keys_, OtpKeysGet(testing::_, testing::_))
      .WillOnce(DoAll(SetArgPointee<1>(rom_key_hdr), Return(kErrorOk)));

  hmac_digest_sha384_t computed_digest;
  for (size_t i = 0; i < kHmacDigestSha384NumWords; ++i) {
    computed_digest.digest[i] = 0x12340000 + i;
  }
  EXPECT_CALL(hmac_, sha384(manifest_key.data, sizeof(manifest_key.data), testing::_))
      .WillOnce(SetArgPointee<2>(computed_digest));

  const sigverify_rom_mldsa_key_t *res_key = nullptr;
  EXPECT_EQ(sigverify_mldsa_key_get(&ctx, key_id, &manifest_key,
                                    kLcStateProd, &res_key),
            kErrorOk);
  EXPECT_EQ(res_key, &mock_otp_key);
}

TEST_F(SigverifyKeysMldsaTest, OtpLookupFailed) {
  sigverify_otp_key_ctx_t ctx;
  sigverify_mldsa87_public_key_t manifest_key;
  std::memset(&manifest_key, 0xa5, sizeof(manifest_key));

  EXPECT_CALL(otp_keys_, OtpKeysGet(testing::_, testing::_))
      .WillOnce(Return(kErrorSigverifyBadKey));

  const sigverify_rom_mldsa_key_t *res_key = nullptr;
  EXPECT_EQ(sigverify_mldsa_key_get(&ctx, 0x12345678, &manifest_key,
                                    kLcStateProd, &res_key),
            kErrorSigverifyBadMldsaKey);
  EXPECT_EQ(res_key, nullptr);
}

TEST_F(SigverifyKeysMldsaTest, DigestMismatch) {
  sigverify_otp_key_ctx_t ctx;
  sigverify_mldsa87_public_key_t manifest_key;
  std::memset(&manifest_key, 0x5a, sizeof(manifest_key));

  sigverify_rom_mldsa_key_t mock_otp_key;
  mock_otp_key.entry.key_type = kSigverifyKeyTypeProd;
  for (size_t i = 0; i < kHmacDigestSha384NumWords; ++i) {
    mock_otp_key.entry.digest.digest[i] = 0x12340000 + i;
  }
  uint32_t key_id = mock_otp_key.entry.digest.digest[0];

  const sigverify_rom_key_header_t *rom_key_hdr = &mock_otp_key.key_header;
  EXPECT_CALL(otp_keys_, OtpKeysGet(testing::_, testing::_))
      .WillOnce(DoAll(SetArgPointee<1>(rom_key_hdr), Return(kErrorOk)));

  hmac_digest_sha384_t computed_digest;
  for (size_t i = 0; i < kHmacDigestSha384NumWords; ++i) {
    computed_digest.digest[i] = 0xdeadbeef + i; // Differing digest
  }
  EXPECT_CALL(hmac_, sha384(manifest_key.data, sizeof(manifest_key.data), testing::_))
      .WillOnce(SetArgPointee<2>(computed_digest));

  const sigverify_rom_mldsa_key_t *res_key = nullptr;
  EXPECT_EQ(sigverify_mldsa_key_get(&ctx, key_id, &manifest_key,
                                    kLcStateProd, &res_key),
            kErrorSigverifyBadMldsaKey);
  EXPECT_EQ(res_key, nullptr);
}

}  // namespace
}  // namespace sigverify_keys_mldsa_unittest
