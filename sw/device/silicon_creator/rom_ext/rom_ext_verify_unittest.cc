#include "sw/device/silicon_creator/rom_ext/rom_ext_verify.h"

#include "gtest/gtest.h"
#include "sw/device/lib/base/hardened.h"
#include "sw/device/silicon_creator/lib/base/boot_measurements.h"
#include "sw/device/silicon_creator/lib/drivers/mock_lifecycle.h"
#include "sw/device/silicon_creator/lib/drivers/mock_otp.h"
#include "sw/device/silicon_creator/lib/drivers/mock_rnd.h"
#include "sw/device/silicon_creator/lib/drivers/mock_hmac.h"
#include "sw/device/silicon_creator/lib/mock_manifest.h"
#include "sw/device/silicon_creator/lib/ownership/mock_owner_verify.h"
#include "sw/device/silicon_creator/lib/sigverify/mock_spx_verify.h"
#include "sw/device/silicon_creator/lib/sigverify/flash_exec.h"
#include "sw/device/silicon_creator/testing/rom_test.h"

namespace rom_ext_verify_unittest {
namespace {
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

enum {
  kSigverifyEcdsaSuccess = 0x2f06b4e0,
};

class RomExtVerifyTest : public rom_test::Unordered<rom_test::RomTest> {
 protected:
  manifest_t manifest_{};
  boot_data_t boot_data_{};
  uint32_t flash_exec_ = 0;
  owner_application_keyring_t keyring_{};
  size_t verify_key_ = 0;
  owner_config_t owner_config_{};
  uint32_t isfb_check_count_ = 0;
  owner_application_key_t key_{};

  rom_test::MockManifest mock_manifest_;
  rom_test::MockLifecycle mock_lifecycle_;
  rom_test::MockOtp mock_otp_;
  rom_test::MockRnd mock_rnd_;
  rom_test::MockHmac mock_hmac_;
  rom_test::MockOwnerVerify mock_owner_verify_;
  rom_test::MockSpxVerify mock_spx_verify_;

  RomExtVerifyTest() {
    // Set up keyring with a default ECDSA key (ID 0)
    key_.header = {
        .tag = kTlvTagApplicationKey,
        .length = sizeof(owner_application_key_t),
    };
    key_.key_alg = kOwnershipKeyAlgEcdsaP256;
    key_.data.id = 0;
    keyring_.length = 1;
    keyring_.key[0] = &key_;

    // Set up default configurations for direct boot path
    manifest_.identifier = CHIP_BL0_IDENTIFIER;
    manifest_.length = CHIP_BL0_SIZE_MIN;
    manifest_.security_version = 1;
    manifest_.manifest_version.major = kManifestVersionMajor2;
    manifest_.length = sizeof(manifest_t) + 0x1000;
    manifest_.signed_region_end = sizeof(manifest_t) + 0x900;
    manifest_.code_start = sizeof(manifest_t);
    manifest_.code_end = sizeof(manifest_t) + 0x800;
    manifest_.entry_point = 0x500;

    boot_data_.min_security_version_bl0 = 1;
    owner_config_.isfb = (owner_isfb_config_t *)kHardenedBoolFalse;
    owner_config_.disable_direct_boot = kHardenedBoolFalse;

    // Set default expectations for mocks to fallback to direct boot (absent cert)
    EXPECT_CALL(mock_manifest_, DelegationCert)
        .Times(AnyNumber())
        .WillRepeatedly(Return(kErrorManifestBadExtension));
    EXPECT_CALL(mock_manifest_, DelegationCertSpx)
        .Times(AnyNumber())
        .WillRepeatedly(Return(kErrorManifestBadExtension));

    EXPECT_CALL(mock_manifest_, SpxKey)
        .Times(AnyNumber())
        .WillRepeatedly(Return(kErrorManifestBadExtension));
    EXPECT_CALL(mock_manifest_, SpxSignature)
        .Times(AnyNumber())
        .WillRepeatedly(Return(kErrorManifestBadExtension));
    ON_CALL(mock_owner_verify_, verify).WillByDefault(DoAll(SetArgPointee<11>(kSigverifyEcdsaSuccess), Return(kErrorOk)));
    ON_CALL(mock_otp_, read32).WillByDefault(Return(0)); // SPX not enabled in OTP
    ON_CALL(mock_lifecycle_, State).WillByDefault(Return(kLcStateProd));

    EXPECT_CALL(mock_hmac_, sha256).Times(AnyNumber());
  }
};

TEST_F(RomExtVerifyTest, DirectBootSuccess) {
  // Expectations for direct boot
  EXPECT_CALL(mock_manifest_, SpxKey).WillOnce(Return(kErrorManifestBadExtension));
  EXPECT_CALL(mock_manifest_, SpxSignature).WillOnce(Return(kErrorManifestBadExtension));

  EXPECT_CALL(mock_rnd_, Uint32).Times(AnyNumber()).WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_lifecycle_, DeviceId);
  EXPECT_CALL(mock_otp_, read32).Times(AnyNumber()).WillRepeatedly(Return(0));
  EXPECT_CALL(mock_lifecycle_, State).Times(AnyNumber()).WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  EXPECT_CALL(mock_owner_verify_, verify).WillOnce(DoAll(SetArgPointee<11>(kSigverifyEcdsaSuccess), Return(kErrorOk)));

  rom_error_t result = rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_,
                                      &keyring_, &verify_key_, &owner_config_,
                                      &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyEcdsaSuccess);
}

TEST_F(RomExtVerifyTest, DirectBootDisabledFails) {
  // If direct boot is disabled and cert is absent, it must fail
  owner_config_.disable_direct_boot = kHardenedBoolTrue;

  rom_error_t result = rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_,
                                      &keyring_, &verify_key_, &owner_config_,
                                      &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidState);
  EXPECT_EQ(flash_exec_, 0);
}

TEST_F(RomExtVerifyTest, DelegateBootEcdsaSuccess) {
  // Create a mock delegation certificate
  manifest_ext_delegation_cert_t cert = {
      .header = {
          .identifier = kManifestExtIdDelegationCert,
          .name = 0,
      },
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints = {
          .min_security_version = 1,
          .max_security_version = 10,
          .allowed_slots = 3, // Slots A and B allowed
          .expiration_epoch = 0,
          .usage_constraint = 0,
          .device_id = {0},
          .manuf_state_creator = 0,
          .manuf_state_owner = 0,
          .life_cycle_state = 0xFFFFFFFF,
      },
      .owner_signature = {{0}},
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kErrorManifestBadExtension));
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));

  // 1. Initial SPX enabled check
  EXPECT_CALL(mock_lifecycle_, State).Times(3).WillRepeatedly(Return(kLcStateProd));

  // 2. Verify delegation cert signature
  EXPECT_CALL(mock_owner_verify_, verify).Times(2).WillRepeatedly(DoAll(SetArgPointee<11>(kSigverifyEcdsaSuccess), Return(kErrorOk)));

  // 3. Check logical constraints & hashing (sigverify_usage_constraints_get x2)
  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  // Hashing execution
  EXPECT_CALL(mock_rnd_, Uint32).Times(AnyNumber()).WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  rom_error_t result = rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_,
                                      &keyring_, &verify_key_, &owner_config_,
                                      &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyEcdsaSuccess);
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintSecVerFails) {
  manifest_ext_delegation_cert_t cert = {
      .header = {
          .identifier = kManifestExtIdDelegationCert,
          .name = 0,
      },
      .constraints = {
          .min_security_version = 5, // Requires SV >= 5
          .max_security_version = 10,
          .allowed_slots = 3,
          .expiration_epoch = 0,
          .usage_constraint = 0,
          .device_id = {0},
          .manuf_state_creator = 0,
          .manuf_state_owner = 0,
          .life_cycle_state = 0xFFFFFFFF,
      },
  };
  // But manifest has SV = 1!
  manifest_.security_version = 1;

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kErrorManifestBadExtension));
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));

  EXPECT_CALL(mock_lifecycle_, State).Times(1).WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify).Times(1).WillRepeatedly(DoAll(SetArgPointee<11>(kSigverifyEcdsaSuccess), Return(kErrorOk)));

  rom_error_t result = rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_,
                                      &keyring_, &verify_key_, &owner_config_,
                                      &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidVersion);
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintSlotFails) {
  manifest_ext_delegation_cert_t cert = {
      .header = {
          .identifier = kManifestExtIdDelegationCert,
          .name = 0,
      },
      .constraints = {
          .min_security_version = 1,
          .max_security_version = 10,
          .allowed_slots = 2, // Allowed slots: B only
          .expiration_epoch = 0,
          .usage_constraint = 0,
          .device_id = {0},
          .manuf_state_creator = 0,
          .manuf_state_owner = 0,
          .life_cycle_state = 0xFFFFFFFF,
      },
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kErrorManifestBadExtension));
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));

  EXPECT_CALL(mock_lifecycle_, State).Times(1).WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify).Times(1).WillRepeatedly(DoAll(SetArgPointee<11>(kSigverifyEcdsaSuccess), Return(kErrorOk)));

  // Booting slot 'A'
  rom_error_t result = rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_,
                                      &keyring_, &verify_key_, &owner_config_,
                                      &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidSlot);
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintDeviceIdFails) {
  manifest_ext_delegation_cert_t cert = {
      .header = {
          .identifier = kManifestExtIdDelegationCert,
          .name = 0,
      },
      .constraints = {
          .min_security_version = 1,
          .max_security_version = 10,
          .allowed_slots = 3,
          .expiration_epoch = 0,
          .usage_constraint = 1 << 0, // Enable device ID check
          .device_id = {0xAA},
          .manuf_state_creator = 0,
          .manuf_state_owner = 0,
          .life_cycle_state = 0xFFFFFFFF,
      },
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kErrorManifestBadExtension));
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));

  // Mock device ID is 0xBB (doesn't match 0xAA)
  lifecycle_device_id_t dev_id = {0xBB};

  EXPECT_CALL(mock_lifecycle_, State).Times(2).WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify).Times(1).WillRepeatedly(DoAll(SetArgPointee<11>(kSigverifyEcdsaSuccess), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId).WillOnce(SetArgPointee<0>(dev_id));
  EXPECT_CALL(mock_otp_, read32).Times(2).WillRepeatedly(Return(0));

  rom_error_t result = rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_,
                                      &keyring_, &verify_key_, &owner_config_,
                                      &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidDeviceId);
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintLifecycleFails) {
  manifest_ext_delegation_cert_t cert = {
      .header = {
          .identifier = kManifestExtIdDelegationCert,
          .name = 0,
      },
      .constraints = {
          .min_security_version = 1,
          .max_security_version = 10,
          .allowed_slots = 3,
          .expiration_epoch = 0,
          .usage_constraint = 1 << kManifestSelectorBitLifeCycleState, // Enable lifecycle check
          .device_id = {0},
          .manuf_state_creator = 0,
          .manuf_state_owner = 0,
          .life_cycle_state = 1 << 2, // Only allow Prod (mask 1 << 2)
      },
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kErrorManifestBadExtension));
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));

  EXPECT_CALL(mock_lifecycle_, State).Times(3).WillRepeatedly(Return(kLcStateDev)); // returns Dev during constraints get & check
  EXPECT_CALL(mock_owner_verify_, verify).Times(1).WillRepeatedly(DoAll(SetArgPointee<11>(kSigverifyEcdsaSuccess), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId);
  EXPECT_CALL(mock_otp_, read32).Times(2).WillRepeatedly(Return(0));

  rom_error_t result = rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_,
                                      &keyring_, &verify_key_, &owner_config_,
                                      &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidLifecycle);
}

TEST_F(RomExtVerifyTest, AttestationOverrideApplied) {
  manifest_ext_delegation_cert_t cert = {
      .header = {
          .identifier = kManifestExtIdDelegationCert,
          .name = 0,
      },
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints = {
          .min_security_version = 1,
          .max_security_version = 10,
          .allowed_slots = 3,
          .expiration_epoch = 0,
          .usage_constraint = 1 << 14, // Attestation override requested! (bit 14)
          .device_id = {0},
          .manuf_state_creator = 0,
          .manuf_state_owner = 0,
          .life_cycle_state = 0xFFFFFFFF,
      },
      .owner_signature = {{0}},
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kErrorManifestBadExtension));
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));

  // Mock returning a specific hash digest in sha256_final
  hmac_digest_t mock_digest = {
      .digest = {0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20}
  };

  EXPECT_CALL(mock_lifecycle_, State).Times(3).WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify).Times(2).WillRepeatedly(DoAll(SetArgPointee<11>(kSigverifyEcdsaSuccess), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  // Hashing execution
  EXPECT_CALL(mock_rnd_, Uint32).Times(AnyNumber()).WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final).WillOnce(SetArgPointee<0>(mock_digest));

  rom_error_t result = rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_,
                                      &keyring_, &verify_key_, &owner_config_,
                                      &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyEcdsaSuccess);

  // Verify that the measurements in global boot_measurements were XORed with 0xDEADBEEF
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(boot_measurements.bl0.data[i], mock_digest.digest[i] ^ 0xDEADBEEF);
  }
}

}  // namespace
}  // namespace rom_ext_verify_unittest
