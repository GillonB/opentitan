// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/rom_ext/rom_ext_verify.h"

#include <string.h>

#include "sw/device/silicon_creator/lib/base/boot_measurements.h"
#include "sw/device/silicon_creator/lib/boot_data.h"
#include "sw/device/silicon_creator/lib/dbg_print.h"
#include "sw/device/silicon_creator/lib/drivers/rnd.h"
#include "sw/device/silicon_creator/lib/error.h"
#include "sw/device/silicon_creator/lib/manifest.h"
#include "sw/device/silicon_creator/lib/ownership/isfb.h"
#include "sw/device/silicon_creator/lib/ownership/owner_block.h"
#include "sw/device/silicon_creator/lib/ownership/owner_verify.h"
#include "sw/device/silicon_creator/lib/sigverify/ecdsa_p256_key.h"
#include "sw/device/silicon_creator/lib/sigverify/spx_verify.h"
#include "sw/device/silicon_creator/lib/sigverify/flash_exec.h"
#include "sw/device/lib/base/bitfield.h"
#include "sw/device/silicon_creator/lib/drivers/lifecycle.h"
#include "sw/device/silicon_creator/lib/sigverify/usage_constraints.h"
#include "sw/device/silicon_creator/rom_ext/rom_ext_boot_policy.h"

enum {
  /**
   * Constant for ECDSA success. Defined here to avoid dependency on
   * ecdsa_p256_verify.h which is incompatible with host-side compilation.
   */
  kSigverifyEcdsaSuccess = 0x2f06b4e0,
};

OT_WARN_UNUSED_RESULT
static rom_error_t verify_direct_boot(const manifest_t *manifest, char slot_id,
                                      const boot_data_t *boot_data, uint32_t *flash_exec,
                                      owner_application_keyring_t *keyring,
                                      size_t *verify_key, owner_config_t *owner_config,
                                      uint32_t *isfb_check_count) {
  uint32_t key_id =
      sigverify_ecdsa_p256_key_id_get(&manifest->ecdsa_public_key);
  // Check if there is an SPX+ key.
  const manifest_ext_spx_key_t *ext_spx_key;
  const manifest_ext_spx_signature_t *ext_spx_signature;
  rom_error_t spx_err = manifest_ext_get_spx_key(manifest, &ext_spx_key);
  spx_err += manifest_ext_get_spx_signature(manifest, &ext_spx_signature);
  switch ((uint32_t)spx_err) {
    case kErrorOk * 2:
      // Both extensions present: valid SPX+ signature.
      key_id ^= sigverify_spx_key_id_get(&ext_spx_key->key);
      break;
    case kErrorManifestBadExtension * 2:
      // Both extensions absent: ECDSA only.
      break;
    default:
      // One present, one absent: bad configuration.
      return kErrorManifestBadExtension;
  }

  RETURN_IF_ERROR(owner_keyring_find_key(keyring, key_id, verify_key));
  uint32_t key_alg = keyring->key[*verify_key]->key_alg;

  if (slot_id) {
    dbg_printf("verify: Slot%c;key%u;%C;%C\r\n", slot_id, (uint32_t)*verify_key,
               key_alg, keyring->key[*verify_key]->key_domain);
  }

  memset(boot_measurements.bl0.data, (int)rnd_uint32(),
         sizeof(boot_measurements.bl0.data));

  hmac_sha256_init();
  // Hash usage constraints.
  manifest_usage_constraints_t usage_constraints_from_hw;
  sigverify_usage_constraints_get(
      manifest->usage_constraints.selector_bits |
          keyring->key[*verify_key]->usage_constraint,
      &usage_constraints_from_hw);
  hmac_sha256_update(&usage_constraints_from_hw,
                     sizeof(usage_constraints_from_hw));
  // Hash the remaining part of the image.
  manifest_digest_region_t digest_region = manifest_digest_region_get(manifest);
  hmac_sha256_update(digest_region.start, digest_region.length);
  // TODO(#19596): add owner configuration block to measurement.
  // Verify signature
  hmac_sha256_process();
  hmac_digest_t act_digest;
  hmac_sha256_final(&act_digest);

  static_assert(sizeof(boot_measurements.bl0) == sizeof(act_digest),
                "Unexpected BL0 digest size.");
  memcpy(&boot_measurements.bl0, &act_digest, sizeof(boot_measurements.bl0));

  const sigverify_spx_signature_t *spx_sig = (spx_err == kErrorOk * 2) ? &ext_spx_signature->signature : NULL;
  RETURN_IF_ERROR(owner_verify(
      key_alg, &keyring->key[*verify_key]->data, &manifest->ecdsa_signature,
      spx_sig, &usage_constraints_from_hw,
      sizeof(usage_constraints_from_hw), NULL, 0, digest_region.start,
      digest_region.length, &act_digest, flash_exec));

  // Perform ISFB checks if the extension is present.
  if ((hardened_bool_t)owner_config->isfb != kHardenedBoolFalse) {
    const manifest_ext_isfb_t *ext_isfb;
    rom_error_t error = manifest_ext_get_isfb(manifest, &ext_isfb);
    if (error == kErrorOk) {
      *isfb_check_count = kHardenedBoolFalse;
      RETURN_IF_ERROR(
          isfb_boot_request_process(ext_isfb, owner_config, isfb_check_count));
      // The previous function returns `kErrorOwnershipISFBFailed` if the strike
      // check or product expression check fails. The following check is to
      // detect any faults.
      HARDENED_CHECK_EQ(*isfb_check_count, isfb_expected_count_get(ext_isfb));
    } else {
      HARDENED_CHECK_NE(error, kErrorOk);
    }
  }

  return kErrorOk;
}

OT_WARN_UNUSED_RESULT
rom_error_t rom_ext_verify(const manifest_t *manifest, char slot_id,
                           const boot_data_t *boot_data, uint32_t *flash_exec,
                           owner_application_keyring_t *keyring,
                           size_t *verify_key, owner_config_t *owner_config,
                           uint32_t *isfb_check_count) {
  RETURN_IF_ERROR(rom_ext_boot_policy_manifest_check(manifest, boot_data));

  // Try to load the base delegation certificate.
  const manifest_ext_delegation_cert_t *cert = NULL;
  rom_error_t cert_err = manifest_ext_get_delegation_cert(manifest, &cert);

  if (cert_err != kErrorOk) {
    if (owner_config->disable_direct_boot == kHardenedBoolTrue) {
      return kErrorOwnershipInvalidState;
    }
    return verify_direct_boot(manifest, slot_id, boot_data, flash_exec, keyring,
                              verify_key, owner_config, isfb_check_count);
  }

  // Retrieve the Silicon Owner Root Key that signed this certificate.
  RETURN_IF_ERROR(owner_keyring_find_key(keyring, cert->owner_key_id, verify_key));
  uint32_t root_key_alg = keyring->key[*verify_key]->key_alg;

  // Determine if SPHINCS+ signature verification is required by OTP.
  uint32_t sigverify_spx_en = sigverify_spx_verify_enabled(lifecycle_state_get());
  bool spx_required = (launder32(sigverify_spx_en) != kSigverifySpxDisabledOtp);

  // Retrieve the optional SPHINCS+ certificate signature extension.
  const manifest_ext_delegation_cert_spx_t *cert_spx = NULL;
  rom_error_t spx_err = manifest_ext_get_delegation_cert_spx(manifest, &cert_spx);
  if (spx_required) {
    if (spx_err != kErrorOk) {
      return kErrorSigverifyBadSpxSignature;
    }
  }

  // Compute SHA256 of the base certificate signed region:
  // Offset 8 (cert->version) to offset 248 (cert->owner_signature). Length = 240 bytes.
  hmac_digest_t cert_digest;
  hmac_sha256((const char *)cert + 8, 240, &cert_digest);

  // Setup root key algorithm for certificate validation. If SPX is disabled in OTP, override to ECDSA only.
  uint32_t root_verify_alg = root_key_alg;
  if (!spx_required) {
    root_verify_alg = kOwnershipKeyAlgEcdsaP256;
  }

  // Verify Delegation Certificate signature(s).
  uint32_t cert_flash_exec = 0;
  const sigverify_spx_signature_t *cert_spx_sig = (cert_spx != NULL) ? &cert_spx->signature : NULL;
  RETURN_IF_ERROR(owner_verify(
      root_verify_alg, &keyring->key[*verify_key]->data, &cert->owner_signature,
      cert_spx_sig, NULL, 0, NULL, 0, NULL, 0, &cert_digest, &cert_flash_exec));
  
  if (root_verify_alg == kOwnershipKeyAlgEcdsaP256) {
    HARDENED_CHECK_EQ(cert_flash_exec, kSigverifyEcdsaSuccess);
  } else {
    HARDENED_CHECK_EQ(cert_flash_exec, kSigverifyFlashExec);
  }

  // Check logical constraints.
  RETURN_IF_ERROR(check_delegation_constraints(manifest, cert, slot_id));

  // Extract the Delegate Public Key(s) from the validated certificate.
  owner_keydata_t delegate_key;
  memset(&delegate_key, 0, sizeof(delegate_key));
  uint32_t delegate_key_alg = cert->delegate_key_alg;
  
  if ((delegate_key_alg & kOwnershipKeyAlgCategoryMask) == kOwnershipKeyAlgCategoryHybrid) {
    delegate_key.hybrid.ecdsa = cert->delegate_public_key;
    if (cert_spx != NULL) {
      delegate_key.hybrid.spx = cert_spx->delegate_spx_key;
    }
  } else {
    delegate_key.ecdsa = cert->delegate_public_key;
  }

  if (slot_id) {
    dbg_printf("verify: Slot%c;delegate;%C;%C\r\n", slot_id, delegate_key_alg,
               keyring->key[*verify_key]->key_domain);
  }

  memset(boot_measurements.bl0.data, (int)rnd_uint32(),
         sizeof(boot_measurements.bl0.data));

  // Prepare measurement hashing
  hmac_sha256_init();
  // Hash usage constraints.
  manifest_usage_constraints_t usage_constraints_from_hw;
  sigverify_usage_constraints_get(
      manifest->usage_constraints.selector_bits |
          cert->constraints.usage_constraint,
      &usage_constraints_from_hw);
  hmac_sha256_update(&usage_constraints_from_hw,
                     sizeof(usage_constraints_from_hw));
  // Hash the remaining part of the image.
  manifest_digest_region_t digest_region = manifest_digest_region_get(manifest);
  hmac_sha256_update(digest_region.start, digest_region.length);
  // Verify signature
  hmac_sha256_process();
  hmac_digest_t act_digest;
  hmac_sha256_final(&act_digest);

  static_assert(sizeof(boot_measurements.bl0) == sizeof(act_digest),
                "Unexpected BL0 digest size.");
  memcpy(&boot_measurements.bl0, &act_digest, sizeof(boot_measurements.bl0));

  // Apply restricted attestation key manager override.
  if (bitfield_bit32_read(cert->constraints.usage_constraint, 14)) {
    for (size_t i = 0; i < ARRAYSIZE(boot_measurements.bl0.data); ++i) {
      boot_measurements.bl0.data[i] ^= 0xDEADBEEF;
    }
  }

  // Setup delegate key algorithm for payload validation. If SPX is disabled in OTP, override to ECDSA only.
  uint32_t delegate_verify_alg = delegate_key_alg;
  if (!spx_required) {
    delegate_verify_alg = kOwnershipKeyAlgEcdsaP256;
  }

  // Retrieve payload SPX signature.
  const manifest_ext_spx_signature_t *payload_spx_signature = NULL;
  rom_error_t payload_spx_err = manifest_ext_get_spx_signature(manifest, &payload_spx_signature);
  const sigverify_spx_signature_t *payload_spx_sig = (payload_spx_err == kErrorOk) ? &payload_spx_signature->signature : NULL;

  RETURN_IF_ERROR(owner_verify(
      delegate_verify_alg, &delegate_key, &manifest->ecdsa_signature,
      payload_spx_sig, &usage_constraints_from_hw,
      sizeof(usage_constraints_from_hw), NULL, 0, digest_region.start,
      digest_region.length, &act_digest, flash_exec));

  // Perform ISFB checks if the extension is present.
  if ((hardened_bool_t)owner_config->isfb != kHardenedBoolFalse) {
    const manifest_ext_isfb_t *ext_isfb;
    rom_error_t error = manifest_ext_get_isfb(manifest, &ext_isfb);
    if (error == kErrorOk) {
      *isfb_check_count = kHardenedBoolFalse;
      RETURN_IF_ERROR(
          isfb_boot_request_process(ext_isfb, owner_config, isfb_check_count));
      HARDENED_CHECK_EQ(*isfb_check_count, isfb_expected_count_get(ext_isfb));
    } else {
      HARDENED_CHECK_NE(error, kErrorOk);
    }
  }

  // This is given that we are expected to perform redundant checks on
  // `flash_exec` and `isfb_check_count`. This is also the reason why don't use
  // `HARDENED_RETURN_IF_ERROR` in the `owner_verify` and `isfb_boot_request`
  // calls.
  return kErrorOk;
}

static uint32_t lifecycle_state_to_mask(lifecycle_state_t state) {
  switch (state) {
    case kLcStateTest:
      return 1u << 0;
    case kLcStateDev:
      return 1u << 1;
    case kLcStateProd:
      return 1u << 2;
    case kLcStateProdEnd:
      return 1u << 3;
    case kLcStateRma:
      return 1u << 4;
    default:
      return 0; // Invalid/unknown state
  }
}

rom_error_t check_delegation_constraints(const manifest_t *manifest,
                                         const manifest_ext_delegation_cert_t *cert,
                                         char slot_id) {
  // Hardened check against security version downgrades
  if (launder32(manifest->security_version) < cert->constraints.min_security_version) {
    return kErrorOwnershipInvalidVersion;
  }
  HARDENED_CHECK_GE(manifest->security_version, cert->constraints.min_security_version);

  // Hardened check against malicious version inflation
  if (launder32(manifest->security_version) > cert->constraints.max_security_version) {
    return kErrorOwnershipInvalidVersion;
  }
  HARDENED_CHECK_LE(manifest->security_version, cert->constraints.max_security_version);

  // Hardened check for allowed_slots
  uint32_t current_slot;
  if (slot_id == 'A') {
    current_slot = 0;
  } else if (slot_id == 'B') {
    current_slot = 1;
  } else {
    return kErrorOwnershipInvalidSlot;
  }
  uint32_t slot_mask = 1u << current_slot;
  if (launder32(cert->constraints.allowed_slots & slot_mask) == 0) {
    return kErrorOwnershipInvalidSlot;
  }
  HARDENED_CHECK_NE(cert->constraints.allowed_slots & slot_mask, 0);

  // Retrieve current hardware constraints
  manifest_usage_constraints_t hw_constraints;
  sigverify_usage_constraints_get(cert->constraints.usage_constraint & 0x7FF, &hw_constraints);

  // Hardened check for device ID
  for (size_t i = 0; i < kLifecycleDeviceIdNumWords; ++i) {
    if (bitfield_bit32_read(cert->constraints.usage_constraint, i)) {
      if (launder32(hw_constraints.device_id.device_id[i]) != cert->constraints.device_id.device_id[i]) {
        return kErrorOwnershipInvalidDeviceId;
      }
      HARDENED_CHECK_EQ(hw_constraints.device_id.device_id[i], cert->constraints.device_id.device_id[i]);
    }
  }

  // Hardened check for manuf_state_creator
  if (bitfield_bit32_read(cert->constraints.usage_constraint, kManifestSelectorBitManufStateCreator)) {
    if (launder32(hw_constraints.manuf_state_creator) != cert->constraints.manuf_state_creator) {
      return kErrorOwnershipInvalidCreatorManufState;
    }
    HARDENED_CHECK_EQ(hw_constraints.manuf_state_creator, cert->constraints.manuf_state_creator);
  }

  // Hardened check for manuf_state_owner
  if (bitfield_bit32_read(cert->constraints.usage_constraint, kManifestSelectorBitManufStateOwner)) {
    if (launder32(hw_constraints.manuf_state_owner) != cert->constraints.manuf_state_owner) {
      return kErrorOwnershipInvalidOwnerManufState;
    }
    HARDENED_CHECK_EQ(hw_constraints.manuf_state_owner, cert->constraints.manuf_state_owner);
  }

  // Hardened check for lifecycle state
  if (bitfield_bit32_read(cert->constraints.usage_constraint, kManifestSelectorBitLifeCycleState)) {
    uint32_t current_lc_mask = lifecycle_state_to_mask(lifecycle_state_get());
    if (launder32(cert->constraints.life_cycle_state & current_lc_mask) == 0) {
      return kErrorOwnershipInvalidLifecycle;
    }
    HARDENED_CHECK_NE(cert->constraints.life_cycle_state & current_lc_mask, 0);
  }

  return kErrorOk;
}
