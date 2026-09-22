#include "sw/device/silicon_creator/lib/sigverify/mock_spx_verify.h"

namespace rom_test {
extern "C" {

uint32_t sigverify_spx_verify_enabled(lifecycle_state_t lc_state) {
  return MockSpxVerify::Instance().Enabled(lc_state);
}

rom_error_t sigverify_spx_verify(
    const sigverify_spx_signature_t *signature, const sigverify_spx_key_t *key,
    const sigverify_spx_config_id_t config, lifecycle_state_t lc_state,
    const void *msg_prefix_1, size_t msg_prefix_1_len, const void *msg_prefix_2,
    size_t msg_prefix_2_len, const void *msg, size_t msg_len,
    const hmac_digest_t *digest, uint32_t *flash_exec) {
  return MockSpxVerify::Instance().Verify(
      signature, key, config, lc_state, msg_prefix_1, msg_prefix_1_len,
      msg_prefix_2, msg_prefix_2_len, msg, msg_len, digest, flash_exec);
}

}  // extern "C"
}  // namespace rom_test
