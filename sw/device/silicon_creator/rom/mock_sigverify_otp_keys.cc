// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/rom/mock_sigverify_otp_keys.h"

namespace rom_test {
extern "C" {

rom_error_t sigverify_otp_keys_init(sigverify_otp_key_ctx_t *ctx) {
  return MockSigverifyOtpKeys::Instance().OtpKeysInit(ctx);
}

rom_error_t sigverify_otp_keys_check(sigverify_otp_key_ctx_t *ctx) {
  return MockSigverifyOtpKeys::Instance().OtpKeysCheck(ctx);
}

rom_error_t sigverify_otp_keys_get(sigverify_otp_keys_get_params_t params,
                                   const sigverify_rom_key_header_t **key) {
  return MockSigverifyOtpKeys::Instance().OtpKeysGet(params, key);
}

}  // extern "C"
}  // namespace rom_test
