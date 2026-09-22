#include "sw/device/silicon_creator/rom_ext/rom_ext_verify.h"

#include "gtest/gtest.h"
#include "sw/device/lib/base/hardened.h"
#include "sw/device/silicon_creator/lib/base/boot_measurements.h"
#include "sw/device/silicon_creator/lib/drivers/mock_hmac.h"
#include "sw/device/silicon_creator/lib/drivers/mock_lifecycle.h"
#include "sw/device/silicon_creator/lib/drivers/mock_otp.h"
#include "sw/device/silicon_creator/lib/drivers/mock_rnd.h"
#include "sw/device/silicon_creator/lib/mock_manifest.h"
#include "sw/device/silicon_creator/lib/ownership/mock_owner_verify.h"
#include "sw/device/silicon_creator/lib/sigverify/flash_exec.h"
#include "sw/device/silicon_creator/lib/sigverify/mock_spx_verify.h"
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
    owner_config_.max_delegation_depth = 2;

    // Set default expectations for mocks to fallback to direct boot (absent
    // cert)
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
    ON_CALL(mock_owner_verify_, verify)
        .WillByDefault(
            DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));
    ON_CALL(mock_otp_, read32)
        .WillByDefault(Return(0));  // SPX not enabled in OTP
    ON_CALL(mock_lifecycle_, State).WillByDefault(Return(kLcStateProd));

    EXPECT_CALL(mock_hmac_, sha256).Times(AnyNumber());
  }
};

TEST_F(RomExtVerifyTest, DirectBootSuccess) {
  // Expectations for direct boot
  EXPECT_CALL(mock_manifest_, SpxKey)
      .WillOnce(Return(kErrorManifestBadExtension));
  EXPECT_CALL(mock_manifest_, SpxSignature)
      .WillOnce(Return(kErrorManifestBadExtension));

  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_lifecycle_, DeviceId);
  EXPECT_CALL(mock_otp_, read32).Times(AnyNumber()).WillRepeatedly(Return(0));
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyFlashExec);
}

TEST_F(RomExtVerifyTest, DirectBootDisabledFails) {
  // If direct boot is disabled and cert is absent, it must fail
  owner_config_.disable_direct_boot = kHardenedBoolTrue;

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidState);
  EXPECT_EQ(flash_exec_, 0);
}

TEST_F(RomExtVerifyTest, DelegateBootEcdsaSuccess) {
  // Create a mock delegation certificate
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,  // Slots A and B allowed
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
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
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(3)
      .WillRepeatedly(Return(kLcStateProd));

  // 2. Verify delegation cert signature
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(2)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  // 3. Check logical constraints & hashing (sigverify_usage_constraints_get x2)
  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  // Hashing execution
  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyFlashExec);
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintSecVerFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .constraints =
          {
              .min_security_version = 5,  // Requires SV >= 5
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
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

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(1)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidVersion);
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintSlotFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 2,  // Allowed slots: B only
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
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

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(1)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  // Booting slot 'A'
  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidSlot);
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintDeviceIdFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 1 << 0,  // Enable device ID check
              .device_id = {0xAA},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
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

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(2)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId).WillOnce(SetArgPointee<0>(dev_id));
  EXPECT_CALL(mock_otp_, read32).Times(2).WillRepeatedly(Return(0));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidDeviceId);
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintLifecycleFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint =
                  1 << kManifestSelectorBitLifeCycleState,  // Enable lifecycle
                                                            // check
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 1 << 2,  // Only allow Prod (mask 1 << 2)
          },
      .owner_signature = {{1}},
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

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(3)
      .WillRepeatedly(
          Return(kLcStateDev));  // returns Dev during constraints get & check
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId);
  EXPECT_CALL(mock_otp_, read32).Times(2).WillRepeatedly(Return(0));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidLifecycle);
}

TEST_F(RomExtVerifyTest, AttestationOverrideApplied) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint =
                  1 << 14,  // Attestation override requested! (bit 14)
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
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
  hmac_digest_t mock_digest = {.digest = {0x01020304, 0x05060708, 0x090a0b0c,
                                          0x0d0e0f10, 0x11121314, 0x15161718,
                                          0x191a1b1c, 0x1d1e1f20}};

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(3)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(2)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  // Hashing execution
  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final).WillOnce(SetArgPointee<0>(mock_digest));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyFlashExec);

  // Verify that the measurements in global boot_measurements were XORed with
  // 0xDEADBEEF
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(boot_measurements.bl0.data[i],
              mock_digest.digest[i] ^ 0xDEADBEEF);
  }
}

TEST_F(RomExtVerifyTest, AttestationOverrideNotAppliedByDefault) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,  // Attestation override NOT set
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
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

  hmac_digest_t mock_digest = {.digest = {0x01020304, 0x05060708, 0x090a0b0c,
                                          0x0d0e0f10, 0x11121314, 0x15161718,
                                          0x191a1b1c, 0x1d1e1f20}};

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(3)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(2)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final).WillOnce(SetArgPointee<0>(mock_digest));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyFlashExec);

  // Measurements must NOT be XORed with 0xDEADBEEF
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(boot_measurements.bl0.data[i], mock_digest.digest[i]);
  }
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintMaxSecVerFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 5,  // Max SV allowed is 5
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };
  // Manifest has security version 8 > max allowed 5
  manifest_.security_version = 8;

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

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(1)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidVersion);
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintSlotBFailsWhenSlotAOnly) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 1,  // Only Slot A allowed (bit 0 = 1)
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
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

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(1)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  // Booting slot 'B' must fail
  rom_error_t result =
      rom_ext_verify(&manifest_, 'B', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidSlot);
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintInvalidSlotChar) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
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

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(1)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  // Slot 'X' is invalid
  rom_error_t result =
      rom_ext_verify(&manifest_, 'X', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidSlot);
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintCreatorManufStateFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint =
                  1 << kManifestSelectorBitManufStateCreator,  // Check creator
                                                               // state
              .device_id = {0},
              .manuf_state_creator = 0x12345678,  // Expected
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
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

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(2)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId);
  // Return different creator state in OTP: 0x99999999 != 0x12345678
  EXPECT_CALL(mock_otp_, read32).Times(2).WillRepeatedly(Return(0x99999999));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidCreatorManufState);
}

TEST_F(RomExtVerifyTest, DelegateBootConstraintOwnerManufStateFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint =
                  1
                  << kManifestSelectorBitManufStateOwner,  // Check owner state
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0xAABBCCDD,  // Expected
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
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

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(2)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId);
  // Return different owner state in OTP: 0x11111111 != 0xAABBCCDD
  EXPECT_CALL(mock_otp_, read32).Times(2).WillRepeatedly(Return(0x11111111));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidOwnerManufState);
}

TEST_F(RomExtVerifyTest, DelegateBootKeyringKeyNotFound) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 99,  // Key 99 does not exist in keyring (only key 0)
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipKeyNotFound);
}

TEST_F(RomExtVerifyTest, DelegateBootOwnerSignatureFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
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

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(1)
      .WillRepeatedly(Return(kLcStateProd));
  // Certificate owner signature verification fails
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(Return(kErrorSigverifyBadEcdsaSignature));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorSigverifyBadEcdsaSignature);
}

TEST_F(RomExtVerifyTest, DelegateBootDelegateSignatureFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
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

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(3)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  // Certificate check passes, but payload BL0 signature verification fails
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)))
      .WillOnce(Return(kErrorSigverifyBadEcdsaSignature));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorSigverifyBadEcdsaSignature);
}

TEST_F(RomExtVerifyTest, DelegateBootHybridSpxSuccess) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgHybridSpxPure,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_spx_t cert_spx = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCertSpx,
              .name = 0,
          },
      .delegate_spx_key = {{0}},
      .signature = {{0}},
  };

  manifest_ext_spx_signature_t payload_spx = {
      .header =
          {
              .identifier = kManifestExtIdSpxSignature,
              .name = 0,
          },
      .signature = {{0}},
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  const manifest_ext_delegation_cert_spx_t *cert_spx_ptr = &cert_spx;
  const manifest_ext_spx_signature_t *payload_spx_ptr = &payload_spx;

  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_spx_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, SpxSignature)
      .Times(AnyNumber())
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(payload_spx_ptr), Return(kErrorOk)));

  // SPX is ENABLED in OTP (return non-disabled value, e.g. 0x1234)
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x1234));

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(3)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(2)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyFlashExec);
}

TEST_F(RomExtVerifyTest, DelegateBootHybridSpxMissingExtensionFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgHybridSpxPure,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  // SPX cert extension is MISSING
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kErrorManifestBadExtension));

  // SPX is ENABLED in OTP
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x1234));

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(1)
      .WillRepeatedly(Return(kLcStateProd));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorSigverifyBadSpxSignature);
}

TEST_F(RomExtVerifyTest, DirectBootDisabledWithValidCertPasses) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  // Direct boot is disabled in owner config
  owner_config_.disable_direct_boot = kHardenedBoolTrue;

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

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(3)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(2)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyFlashExec);
}

TEST_F(RomExtVerifyTest, DelegateBootHybridSpxPrehashSuccess) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgHybridSpxPrehash,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_spx_t cert_spx = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCertSpx,
              .name = 0,
          },
      .delegate_spx_key = {{0}},
      .signature = {{0}},
  };

  manifest_ext_spx_signature_t payload_spx = {
      .header =
          {
              .identifier = kManifestExtIdSpxSignature,
              .name = 0,
          },
      .signature = {{0}},
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  const manifest_ext_delegation_cert_spx_t *cert_spx_ptr = &cert_spx;
  const manifest_ext_spx_signature_t *payload_spx_ptr = &payload_spx;

  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_spx_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, SpxSignature)
      .Times(AnyNumber())
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(payload_spx_ptr), Return(kErrorOk)));

  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x1234));

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(3)
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(2)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyFlashExec);
}

TEST_F(RomExtVerifyTest, DelegateBootHybridSpxOwnerCertSpxSignatureFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgHybridSpxPure,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_spx_t cert_spx = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCertSpx,
              .name = 0,
          },
      .delegate_spx_key = {{0}},
      .signature = {{0}},
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  const manifest_ext_delegation_cert_spx_t *cert_spx_ptr = &cert_spx;

  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_spx_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x1234));

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(1)
      .WillRepeatedly(Return(kLcStateProd));
  // Certificate check owner SPX signature fails
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(Return(kErrorSigverifyBadSpxSignature));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorSigverifyBadSpxSignature);
}

TEST_F(RomExtVerifyTest, DelegateBootHybridSpxOwnerCertEcdsaSignatureFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgHybridSpxPure,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_spx_t cert_spx = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCertSpx,
              .name = 0,
          },
      .delegate_spx_key = {{0}},
      .signature = {{0}},
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  const manifest_ext_delegation_cert_spx_t *cert_spx_ptr = &cert_spx;

  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_spx_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x1234));

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(1)
      .WillRepeatedly(Return(kLcStateProd));
  // Certificate check owner ECDSA signature fails
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(Return(kErrorSigverifyBadEcdsaSignature));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorSigverifyBadEcdsaSignature);
}

TEST_F(RomExtVerifyTest, DelegateBootHybridSpxPayloadEcdsaSignatureFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgHybridSpxPure,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_spx_t cert_spx = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCertSpx,
              .name = 0,
          },
      .delegate_spx_key = {{0}},
      .signature = {{0}},
  };

  manifest_ext_spx_signature_t payload_spx = {
      .header =
          {
              .identifier = kManifestExtIdSpxSignature,
              .name = 0,
          },
      .signature = {{0}},
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  const manifest_ext_delegation_cert_spx_t *cert_spx_ptr = &cert_spx;
  const manifest_ext_spx_signature_t *payload_spx_ptr = &payload_spx;

  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_spx_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, SpxSignature)
      .Times(AnyNumber())
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(payload_spx_ptr), Return(kErrorOk)));

  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x1234));

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(3)
      .WillRepeatedly(Return(kLcStateProd));
  // Certificate check passes, but payload ECDSA signature verification fails
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)))
      .WillOnce(Return(kErrorSigverifyBadEcdsaSignature));

  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorSigverifyBadEcdsaSignature);
}

TEST_F(RomExtVerifyTest, DelegateBootHybridSpxPayloadSpxSignatureFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgHybridSpxPure,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_spx_t cert_spx = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCertSpx,
              .name = 0,
          },
      .delegate_spx_key = {{0}},
      .signature = {{0}},
  };

  manifest_ext_spx_signature_t payload_spx = {
      .header =
          {
              .identifier = kManifestExtIdSpxSignature,
              .name = 0,
          },
      .signature = {{0}},
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  const manifest_ext_delegation_cert_spx_t *cert_spx_ptr = &cert_spx;
  const manifest_ext_spx_signature_t *payload_spx_ptr = &payload_spx;

  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_spx_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, SpxSignature)
      .Times(AnyNumber())
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(payload_spx_ptr), Return(kErrorOk)));

  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x1234));

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(3)
      .WillRepeatedly(Return(kLcStateProd));
  // Certificate check passes, but payload SPX signature verification fails
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)))
      .WillOnce(Return(kErrorSigverifyBadSpxSignature));

  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorSigverifyBadSpxSignature);
}

TEST_F(RomExtVerifyTest, DelegateBootHybridSpxOtpDisabledFallback) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgHybridSpxPure,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_spx_t cert_spx = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCertSpx,
              .name = 0,
          },
      .delegate_spx_key = {{0}},
      .signature = {{0}},
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  const manifest_ext_delegation_cert_spx_t *cert_spx_ptr = &cert_spx;

  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_spx_ptr), Return(kErrorOk)));

  // SPX is DISABLED in OTP (kSigverifySpxSuccess / kSigverifySpxDisabledOtp =
  // 0x8d6c8c17)
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(3)
      .WillRepeatedly(Return(kLcStateProd));
  // Falls back to ECDSA only for payload verification
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(2)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));
  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyFlashExec);
}

TEST_F(RomExtVerifyTest, DelegateBootHybridSpxMissingPayloadSignatureFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgHybridSpxPure,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_spx_t cert_spx = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCertSpx,
              .name = 0,
          },
      .delegate_spx_key = {{0}},
      .signature = {{0}},
  };

  const manifest_ext_delegation_cert_t *cert_ptr = &cert;
  const manifest_ext_delegation_cert_spx_t *cert_spx_ptr = &cert_spx;

  EXPECT_CALL(mock_manifest_, DelegationCert)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_ptr), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .Times(AnyNumber())
      .WillRepeatedly(DoAll(SetArgPointee<1>(cert_spx_ptr), Return(kErrorOk)));

  // Payload SPHINCS+ signature extension is MISSING from BL0 manifest
  EXPECT_CALL(mock_manifest_, SpxSignature)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kErrorManifestBadExtension));

  // SPX is ENABLED in OTP
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x1234));

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(3)
      .WillRepeatedly(Return(kLcStateProd));
  // Certificate check passes (call 1), but payload verify (call 2) fails
  // because payload_spx_sig is NULL
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)))
      .WillOnce(Return(kErrorSigverifyBadSpxSignature));

  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));

  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorSigverifyBadSpxSignature);
}

TEST_F(RomExtVerifyTest, DelegateBootTier2Success) {
  manifest_ext_delegation_cert_t cert_inter = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeIntermediate,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_t cert_leaf = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 9,
              .allowed_slots = 1,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  mock_manifest_.use_delegation_certs = true;
  EXPECT_CALL(mock_manifest_, DelegationCerts)
      .WillOnce(::testing::Invoke(
          [&](const manifest_t *, size_t max_certs,
              const manifest_ext_delegation_cert_t **certs,
              const manifest_ext_delegation_cert_spx_t **certs_spx,
              size_t *cert_count) {
            certs[0] = &cert_inter;
            certs[1] = &cert_leaf;
            *cert_count = 2;
            return kErrorOk;
          }));

  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));

  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProd));

  // 1. Verify intermediate cert with root key
  // 2. Verify leaf cert with intermediate delegate key
  // 3. Verify BL0 payload with leaf delegate key
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(3)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(AnyNumber());
  EXPECT_CALL(mock_otp_, read32).Times(AnyNumber()).WillRepeatedly(Return(0));
  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init).Times(AnyNumber());
  EXPECT_CALL(mock_hmac_, sha256_update).Times(AnyNumber());
  EXPECT_CALL(mock_manifest_, DigestRegion).Times(AnyNumber());
  EXPECT_CALL(mock_hmac_, sha256_process).Times(AnyNumber());
  EXPECT_CALL(mock_hmac_, sha256_final).Times(AnyNumber());

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyFlashExec);
}

TEST_F(RomExtVerifyTest, DelegateBootTier2CertTypeOrderingInvalid) {
  manifest_ext_delegation_cert_t cert_first = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,  // Invalid: index 0 should be INTR
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_t cert_second = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  mock_manifest_.use_delegation_certs = true;
  EXPECT_CALL(mock_manifest_, DelegationCerts)
      .WillOnce(::testing::Invoke(
          [&](const manifest_t *, size_t max_certs,
              const manifest_ext_delegation_cert_t **certs,
              const manifest_ext_delegation_cert_spx_t **certs_spx,
              size_t *cert_count) {
            certs[0] = &cert_first;
            certs[1] = &cert_second;
            *cert_count = 2;
            return kErrorOk;
          }));

  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProd));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidCertType);
}

TEST_F(RomExtVerifyTest, DelegateBootTier2CertTypeLeafAsIntermediateInvalid) {
  manifest_ext_delegation_cert_t cert_first = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeIntermediate,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_t cert_second = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeIntermediate,  // Invalid: final cert should be LEAF
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  mock_manifest_.use_delegation_certs = true;
  EXPECT_CALL(mock_manifest_, DelegationCerts)
      .WillOnce(::testing::Invoke(
          [&](const manifest_t *, size_t max_certs,
              const manifest_ext_delegation_cert_t **certs,
              const manifest_ext_delegation_cert_spx_t **certs_spx,
              size_t *cert_count) {
            certs[0] = &cert_first;
            certs[1] = &cert_second;
            *cert_count = 2;
            return kErrorOk;
          }));

  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidCertType);
}

TEST_F(RomExtVerifyTest, DelegateBootTier2PolicySubsettingMinVersionFails) {
  manifest_ext_delegation_cert_t cert_inter = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeIntermediate,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 5,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_t cert_leaf = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version =
                  4,  // Invalid: child min (4) < parent min (5)
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  mock_manifest_.use_delegation_certs = true;
  EXPECT_CALL(mock_manifest_, DelegationCerts)
      .WillOnce(::testing::Invoke(
          [&](const manifest_t *, size_t max_certs,
              const manifest_ext_delegation_cert_t **certs,
              const manifest_ext_delegation_cert_spx_t **certs_spx,
              size_t *cert_count) {
            certs[0] = &cert_inter;
            certs[1] = &cert_leaf;
            *cert_count = 2;
            return kErrorOk;
          }));

  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidPolicySubsetting);
}

TEST_F(RomExtVerifyTest, DelegateBootTier2PolicySubsettingSlotsFails) {
  manifest_ext_delegation_cert_t cert_inter = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeIntermediate,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 1,  // Only Slot A allowed by parent
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_t cert_leaf = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots =
                  3,  // Invalid: child requests Slot A and B (3 & ~1 = 2 != 0)
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  mock_manifest_.use_delegation_certs = true;
  EXPECT_CALL(mock_manifest_, DelegationCerts)
      .WillOnce(::testing::Invoke(
          [&](const manifest_t *, size_t max_certs,
              const manifest_ext_delegation_cert_t **certs,
              const manifest_ext_delegation_cert_spx_t **certs_spx,
              size_t *cert_count) {
            certs[0] = &cert_inter;
            certs[1] = &cert_leaf;
            *cert_count = 2;
            return kErrorOk;
          }));

  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidPolicySubsetting);
}

TEST_F(RomExtVerifyTest, DelegateBootTier2DepthExceededFails) {
  manifest_ext_delegation_cert_t cert_inter = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeIntermediate,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_t cert_leaf = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  // Limit max delegation depth to 1 (only single-tier leaf allowed)
  owner_config_.max_delegation_depth = 1;

  mock_manifest_.use_delegation_certs = true;
  EXPECT_CALL(mock_manifest_, DelegationCerts)
      .WillOnce(::testing::Invoke(
          [&](const manifest_t *, size_t max_certs,
              const manifest_ext_delegation_cert_t **certs,
              const manifest_ext_delegation_cert_spx_t **certs_spx,
              size_t *cert_count) {
            certs[0] = &cert_inter;
            certs[1] = &cert_leaf;
            *cert_count = 2;
            return kErrorOk;
          }));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidDelegationDepth);
}

TEST_F(RomExtVerifyTest, DelegateBootCertErrFailClosed) {
  mock_manifest_.use_delegation_certs = true;
  EXPECT_CALL(mock_manifest_, DelegationCerts)
      .WillOnce(Return(kErrorManifestBadExtension));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorManifestBadExtension);
}

TEST_F(RomExtVerifyTest,
       DelegateBootConstraintMinSecVerGreaterThanMaxSecVerFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 10,
              .max_security_version = 5,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  EXPECT_CALL(mock_manifest_, DelegationCert)
      .WillOnce(DoAll(SetArgPointee<1>(&cert), Return(kErrorOk)));
  EXPECT_CALL(mock_manifest_, DelegationCertSpx)
      .WillOnce(Return(kErrorManifestBadExtension));
  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxDisabledOtp));
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidVersion);
}

TEST_F(RomExtVerifyTest, DelegateBootTier2ChildZeroAllowedSlotsFails) {
  manifest_ext_delegation_cert_t cert_inter = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeIntermediate,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_t cert_leaf = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 0,  // Invalid: child requests 0 allowed slots
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  mock_manifest_.use_delegation_certs = true;
  EXPECT_CALL(mock_manifest_, DelegationCerts)
      .WillOnce(::testing::Invoke(
          [&](const manifest_t *, size_t max_certs,
              const manifest_ext_delegation_cert_t **certs,
              const manifest_ext_delegation_cert_spx_t **certs_spx,
              size_t *cert_count) {
            certs[0] = &cert_inter;
            certs[1] = &cert_leaf;
            *cert_count = 2;
            return kErrorOk;
          }));

  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidPolicySubsetting);
}

TEST_F(RomExtVerifyTest, DelegateBootTier2ExpirationEpochContainmentFails) {
  manifest_ext_delegation_cert_t cert_inter = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeIntermediate,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 100,  // Parent has expiration epoch
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_t cert_leaf = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch =
                  0,  // Invalid: child does not inherit expiration epoch
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  mock_manifest_.use_delegation_certs = true;
  EXPECT_CALL(mock_manifest_, DelegationCerts)
      .WillOnce(::testing::Invoke(
          [&](const manifest_t *, size_t max_certs,
              const manifest_ext_delegation_cert_t **certs,
              const manifest_ext_delegation_cert_spx_t **certs_spx,
              size_t *cert_count) {
            certs[0] = &cert_inter;
            certs[1] = &cert_leaf;
            *cert_count = 2;
            return kErrorOk;
          }));

  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidPolicySubsetting);
}

TEST_F(RomExtVerifyTest, DelegateBootTier2HybridDowngradeFails) {
  manifest_ext_delegation_cert_t cert_inter = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeIntermediate,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgHybridSpxPure,  // Hybrid
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_t cert_leaf = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,  // Downgrade to ECDSA
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_spx_t spx_inter = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCertSpx,
              .name = 0,
          },
      .delegate_spx_key = {{0}},
      .signature = {{0}},
  };

  mock_manifest_.use_delegation_certs = true;
  EXPECT_CALL(mock_manifest_, DelegationCerts)
      .WillOnce(::testing::Invoke(
          [&](const manifest_t *, size_t max_certs,
              const manifest_ext_delegation_cert_t **certs,
              const manifest_ext_delegation_cert_spx_t **certs_spx,
              size_t *cert_count) {
            certs[0] = &cert_inter;
            certs[1] = &cert_leaf;
            certs_spx[0] = &spx_inter;
            *cert_count = 2;
            return kErrorOk;
          }));

  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidPolicySubsetting);
}

TEST_F(RomExtVerifyTest,
       DelegateBootTier2AttestationOverrideMissingInChildFails) {
  manifest_ext_delegation_cert_t cert_inter = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeIntermediate,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = (1u << 14),  // Parent has Bit 14 set
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  manifest_ext_delegation_cert_t cert_leaf = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,  // Child missing Bit 14
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{1}},
  };

  mock_manifest_.use_delegation_certs = true;
  EXPECT_CALL(mock_manifest_, DelegationCerts)
      .WillOnce(::testing::Invoke(
          [&](const manifest_t *, size_t max_certs,
              const manifest_ext_delegation_cert_t **certs,
              const manifest_ext_delegation_cert_spx_t **certs_spx,
              size_t *cert_count) {
            certs[0] = &cert_inter;
            certs[1] = &cert_leaf;
            *cert_count = 2;
            return kErrorOk;
          }));

  EXPECT_CALL(mock_spx_verify_, Enabled)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kSigverifySpxSuccess));
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify)
      .WillOnce(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOwnershipInvalidPolicySubsetting);
}

TEST_F(RomExtVerifyTest, EmptyCertSignatureInNonProdDevPasses) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{0}},  // Empty signature
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

  // State is Dev (non-production)
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateDev));
  // Cert verification is bypassed for empty signature, so only 1 owner_verify
  // call for payload
  EXPECT_CALL(mock_owner_verify_, verify)
      .Times(1)
      .WillRepeatedly(
          DoAll(SetArgPointee<11>(kSigverifyFlashExec), Return(kErrorOk)));

  EXPECT_CALL(mock_lifecycle_, DeviceId).Times(2);
  EXPECT_CALL(mock_otp_, read32).Times(4).WillRepeatedly(Return(0));
  EXPECT_CALL(mock_rnd_, Uint32)
      .Times(AnyNumber())
      .WillRepeatedly(Return(0x12345678));
  EXPECT_CALL(mock_hmac_, sha256_init);
  EXPECT_CALL(mock_hmac_, sha256_update).Times(2);
  EXPECT_CALL(mock_manifest_, DigestRegion);
  EXPECT_CALL(mock_hmac_, sha256_process);
  EXPECT_CALL(mock_hmac_, sha256_final);

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorOk);
  EXPECT_EQ(flash_exec_, kSigverifyFlashExec);
}

TEST_F(RomExtVerifyTest, EmptyCertSignatureInProdFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{0}},  // Empty signature
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

  // In Prod lifecycle, empty certificate signatures must fail closed
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProd));
  EXPECT_CALL(mock_owner_verify_, verify).Times(0);

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorSigverifyBadEcdsaSignature);
}

TEST_F(RomExtVerifyTest, EmptyCertSignatureInProdEndFails) {
  manifest_ext_delegation_cert_t cert = {
      .header =
          {
              .identifier = kManifestExtIdDelegationCert,
              .name = 0,
          },
      .cert_type = kCertTypeLeaf,
      .version = 1,
      .owner_key_id = 0,
      .delegate_key_alg = kOwnershipKeyAlgEcdsaP256,
      .delegate_public_key = {{0}},
      .constraints =
          {
              .min_security_version = 1,
              .max_security_version = 10,
              .allowed_slots = 3,
              .expiration_epoch = 0,
              .usage_constraint = 0,
              .device_id = {0},
              .manuf_state_creator = 0,
              .manuf_state_owner = 0,
              .life_cycle_state = 0xFFFFFFFF,
          },
      .owner_signature = {{0}},  // Empty signature
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

  // In ProdEnd lifecycle, empty certificate signatures must fail closed
  EXPECT_CALL(mock_lifecycle_, State)
      .Times(AnyNumber())
      .WillRepeatedly(Return(kLcStateProdEnd));
  EXPECT_CALL(mock_owner_verify_, verify).Times(0);

  rom_error_t result =
      rom_ext_verify(&manifest_, 'A', &boot_data_, &flash_exec_, &keyring_,
                     &verify_key_, &owner_config_, &isfb_check_count_);
  EXPECT_EQ(result, kErrorSigverifyBadEcdsaSignature);
}

}  // namespace
}  // namespace rom_ext_verify_unittest
