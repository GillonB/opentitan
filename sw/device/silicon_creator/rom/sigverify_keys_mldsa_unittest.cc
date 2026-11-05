// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/rom/sigverify_keys_mldsa.h"

#include <cstring>

#include "gtest/gtest.h"
#include "sw/device/lib/base/global_mock.h"
#include "sw/device/lib/base/hardened.h"
#include "sw/device/silicon_creator/lib/error.h"
#include "sw/device/silicon_creator/lib/sigverify/mldsa87_key.h"
#include "sw/device/silicon_creator/rom/mock_sigverify_otp_keys.h"
#include "sw/device/silicon_creator/testing/rom_test.h"

namespace sigverify_keys_mldsa_unittest {
namespace {
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

class MockSigverifyMldsaKey
    : public global_mock::GlobalMock<MockSigverifyMldsaKey> {
 public:
  MOCK_METHOD(rom_error_t, ComputeTr,
              (const sigverify_mldsa87_public_key_t *, uint32_t *));
};

}  // namespace

extern "C" {
rom_error_t mldsa_compute_tr(const sigverify_mldsa87_public_key_t *key,
                             uint32_t *tr) {
  return MockSigverifyMldsaKey::Instance().ComputeTr(key, tr);
}
}  // extern "C"

namespace {

class SigverifyKeysMldsaTest : public rom_test::RomTest {
 protected:
  testing::StrictMock<MockSigverifyMldsaKey> mldsa_key_;
  rom_test::MockSigverifyOtpKeys otp_keys_;
};

TEST_F(SigverifyKeysMldsaTest, Success) {
  sigverify_otp_key_ctx_t ctx;
  sigverify_mldsa87_public_key_t manifest_key;
  std::memset(&manifest_key, 0x5a, sizeof(manifest_key));

  sigverify_rom_mldsa_key_t mock_otp_key;
  mock_otp_key.entry.key_type = kSigverifyKeyTypeProd;
  // Set mock 48-byte digest in OTP (12 words)
  for (size_t i = 0; i < kSigverifyMldsa87KeyDigestWords; ++i) {
    mock_otp_key.entry.digest.digest[i] = 0x12340000 + i;
  }
  uint32_t key_id = mock_otp_key.entry.digest.digest[0];

  const sigverify_rom_key_header_t *rom_key_hdr = &mock_otp_key.key_header;
  EXPECT_CALL(otp_keys_, OtpKeysGet(testing::_, testing::_))
      .WillOnce(DoAll(SetArgPointee<1>(rom_key_hdr), Return(kErrorOk)));

  // Mock computed tr = SHAKE256(pk, 64) (16 words, first 12 words match OTP)
  uint32_t computed_tr[kMldsa87TrWords];
  for (size_t i = 0; i < kSigverifyMldsa87KeyDigestWords; ++i) {
    computed_tr[i] = 0x12340000 + i;
  }
  for (size_t i = kSigverifyMldsa87KeyDigestWords; i < kMldsa87TrWords; ++i) {
    computed_tr[i] = 0x56780000 + i;
  }
  EXPECT_CALL(mldsa_key_, ComputeTr(&manifest_key, testing::_))
      .WillOnce([&computed_tr](const sigverify_mldsa87_public_key_t *,
                               uint32_t *tr) {
        std::memcpy(tr, computed_tr, sizeof(computed_tr));
        return kErrorOk;
      });

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
  for (size_t i = 0; i < kSigverifyMldsa87KeyDigestWords; ++i) {
    mock_otp_key.entry.digest.digest[i] = 0x12340000 + i;
  }
  uint32_t key_id = mock_otp_key.entry.digest.digest[0];

  const sigverify_rom_key_header_t *rom_key_hdr = &mock_otp_key.key_header;
  EXPECT_CALL(otp_keys_, OtpKeysGet(testing::_, testing::_))
      .WillOnce(DoAll(SetArgPointee<1>(rom_key_hdr), Return(kErrorOk)));

  // Mock computed tr having differing prefix
  uint32_t computed_tr[kMldsa87TrWords];
  for (size_t i = 0; i < kMldsa87TrWords; ++i) {
    computed_tr[i] = 0xdeadbeef + i;
  }
  EXPECT_CALL(mldsa_key_, ComputeTr(&manifest_key, testing::_))
      .WillOnce([&computed_tr](const sigverify_mldsa87_public_key_t *,
                               uint32_t *tr) {
        std::memcpy(tr, computed_tr, sizeof(computed_tr));
        return kErrorOk;
      });

  const sigverify_rom_mldsa_key_t *res_key = nullptr;
  EXPECT_EQ(sigverify_mldsa_key_get(&ctx, key_id, &manifest_key,
                                    kLcStateProd, &res_key),
            kErrorSigverifyBadMldsaKey);
  EXPECT_EQ(res_key, nullptr);
}

TEST_F(SigverifyKeysMldsaTest, ComputeTrFailed) {
  sigverify_otp_key_ctx_t ctx;
  sigverify_mldsa87_public_key_t manifest_key;
  std::memset(&manifest_key, 0x5a, sizeof(manifest_key));

  sigverify_rom_mldsa_key_t mock_otp_key;
  mock_otp_key.entry.key_type = kSigverifyKeyTypeProd;
  for (size_t i = 0; i < kSigverifyMldsa87KeyDigestWords; ++i) {
    mock_otp_key.entry.digest.digest[i] = 0x12340000 + i;
  }
  uint32_t key_id = mock_otp_key.entry.digest.digest[0];

  const sigverify_rom_key_header_t *rom_key_hdr = &mock_otp_key.key_header;
  EXPECT_CALL(otp_keys_, OtpKeysGet(testing::_, testing::_))
      .WillOnce(DoAll(SetArgPointee<1>(rom_key_hdr), Return(kErrorOk)));

  EXPECT_CALL(mldsa_key_, ComputeTr(&manifest_key, testing::_))
      .WillOnce(Return(kErrorUnknown));

  const sigverify_rom_mldsa_key_t *res_key = nullptr;
  EXPECT_EQ(sigverify_mldsa_key_get(&ctx, key_id, &manifest_key,
                                    kLcStateProd, &res_key),
            kErrorUnknown);
  EXPECT_EQ(res_key, nullptr);
}

}  // namespace
}  // namespace sigverify_keys_mldsa_unittest
