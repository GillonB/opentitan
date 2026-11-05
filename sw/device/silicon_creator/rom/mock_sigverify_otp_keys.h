// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_MOCK_SIGVERIFY_OTP_KEYS_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_MOCK_SIGVERIFY_OTP_KEYS_H_

#include "sw/device/lib/base/global_mock.h"
#include "sw/device/silicon_creator/rom/sigverify_otp_keys.h"
#include "sw/device/silicon_creator/testing/rom_test.h"

namespace rom_test {
namespace internal {

/**
 * Mock class for sigverify_otp_keys.
 */
class MockSigverifyOtpKeys : public global_mock::GlobalMock<MockSigverifyOtpKeys> {
 public:
  MOCK_METHOD(rom_error_t, OtpKeysInit, (sigverify_otp_key_ctx_t *));
  MOCK_METHOD(rom_error_t, OtpKeysCheck, (sigverify_otp_key_ctx_t *));
  MOCK_METHOD(rom_error_t, OtpKeysGet,
              (sigverify_otp_keys_get_params_t,
               const sigverify_rom_key_header_t **));
};

}  // namespace internal

using MockSigverifyOtpKeys = testing::StrictMock<internal::MockSigverifyOtpKeys>;

}  // namespace rom_test

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_MOCK_SIGVERIFY_OTP_KEYS_H_
