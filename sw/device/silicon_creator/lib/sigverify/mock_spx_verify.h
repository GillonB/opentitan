#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_SIGVERIFY_MOCK_SPX_VERIFY_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_SIGVERIFY_MOCK_SPX_VERIFY_H_

#include "sw/device/lib/base/global_mock.h"
#include "sw/device/silicon_creator/lib/sigverify/spx_verify.h"
#include "sw/device/silicon_creator/testing/rom_test.h"

namespace rom_test {
namespace internal {

class MockSpxVerify : public global_mock::GlobalMock<MockSpxVerify> {
 public:
  MOCK_METHOD(uint32_t, Enabled, (lifecycle_state_t));
  MOCK_METHOD(rom_error_t, Verify,
              (const sigverify_spx_signature_t *, const sigverify_spx_key_t *,
               const sigverify_spx_config_id_t, lifecycle_state_t,
               const void *, size_t, const void *, size_t, const void *, size_t,
               const hmac_digest_t *, uint32_t *));
};

}  // namespace internal

using MockSpxVerify = testing::StrictMock<internal::MockSpxVerify>;

}  // namespace rom_test

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_LIB_SIGVERIFY_MOCK_SPX_VERIFY_H_
