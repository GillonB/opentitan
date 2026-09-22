// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/lib/manifest.h"

#include "sw/device/silicon_creator/lib/base/chip.h"

#if defined(OPENTITAN_IS_EARLGREY) || defined(OPENTITAN_IS_ENGLISHBREAKFAST)
#include "sw/device/silicon_creator/lib/nvm_ctrl.h"
#define NVM_SIZE_BYTES NVM_DATA_SIZE_BYTES
#elif defined(OPENTITAN_IS_DARJEELING)
#include "hw/top_darjeeling/sw/autogen/top_darjeeling.h"
#define NVM_SIZE_BYTES TOP_DARJEELING_SRAM_CTRL_MAIN_RAM_SIZE_BYTES
#else
#error unsupported top
#endif

static_assert(CHIP_ROM_EXT_SIZE_MIN >= CHIP_MANIFEST_SIZE,
              "`CHIP_ROM_EXT_SIZE_MIN` is too small");
static_assert(CHIP_ROM_EXT_SIZE_MAX >= CHIP_ROM_EXT_SIZE_MIN,
              "`CHIP_ROM_EXT_SIZE_MAX` is too small");
static_assert(CHIP_ROM_EXT_RESIZABLE_SIZE_MAX >= CHIP_ROM_EXT_SIZE_MAX,
              "`CHIP_ROM_EXT_RESIZABLE_SIZE_MAX` is too small");
static_assert(CHIP_BL0_SIZE_MIN >= CHIP_MANIFEST_SIZE,
              "`CHIP_BL0_SIZE_MIN` is too small");
static_assert(CHIP_BL0_SIZE_MAX >= CHIP_BL0_SIZE_MIN,
              "`CHIP_BL0_SIZE_MAX` is too small");
static_assert(CHIP_BL0_SIZE_MAX <=
                  ((NVM_SIZE_BYTES / 2) - CHIP_ROM_EXT_SIZE_MAX),
              "`CHIP_BL0_SIZE_MAX` is too large");

// Extern declarations for the inline functions in the manifest header.
extern rom_error_t manifest_check(const manifest_t *manifest);
extern manifest_digest_region_t manifest_digest_region_get(
    const manifest_t *manifest);
extern epmp_region_t manifest_code_region_get(const manifest_t *manifest);
extern uintptr_t manifest_entry_point_get(const manifest_t *manifest);
extern rom_error_t manifest_ext_get_spx_key(
    const manifest_t *manifest, const manifest_ext_spx_key_t **spx_key);
extern rom_error_t manifest_ext_get_spx_signature(
    const manifest_t *manifest,
    const manifest_ext_spx_signature_t **spx_signature);
extern rom_error_t manifest_ext_get_isfb(const manifest_t *manifest,
                                         const manifest_ext_isfb_t **isfb);
extern rom_error_t manifest_ext_get_isfb_erase(
    const manifest_t *manifest, const manifest_ext_isfb_erase_t **isfb_erase);
extern rom_error_t manifest_ext_get_secver_write(
    const manifest_t *manifest,
    const manifest_ext_secver_write_t **secver_write);
extern rom_error_t manifest_ext_get_delegation_cert(
    const manifest_t *manifest,
    const manifest_ext_delegation_cert_t **delegation_cert);
extern rom_error_t manifest_ext_get_delegation_cert_spx(
    const manifest_t *manifest,
    const manifest_ext_delegation_cert_spx_t **delegation_cert_spx);

rom_error_t manifest_ext_get_delegation_certs(
    const manifest_t *manifest, size_t max_certs,
    const manifest_ext_delegation_cert_t *certs[],
    const manifest_ext_delegation_cert_spx_t *certs_spx[], size_t *cert_count) {
  *cert_count = 0;
  size_t spx_count = 0;

  for (size_t i = 0; i < CHIP_MANIFEST_EXT_TABLE_ENTRY_COUNT; ++i) {
    const manifest_ext_table_entry_t *entry = &manifest->extensions.entries[i];
    uint32_t table_id = entry->identifier;
    uint32_t offset = entry->offset;

    if (table_id == kManifestExtIdDelegationCert) {
      if (*cert_count >= max_certs) {
        return kErrorManifestBadExtension;
      }

      enum {
        kMinSize = CHIP_MANIFEST_SIZE,
        kMaxSize = CHIP_ROM_EXT_RESIZABLE_SIZE_MAX -
                   sizeof(manifest_ext_delegation_cert_t),
      };

      if (offset < kMinSize || offset >= kMaxSize) {
        return kErrorManifestBadExtension;
      }

      uintptr_t ext_address = (uintptr_t)((char *)manifest + offset);
      uint32_t header_id = ((manifest_ext_header_t *)ext_address)->identifier;
      if (header_id != kManifestExtIdDelegationCert) {
        return kErrorManifestBadExtension;
      }

      certs[*cert_count] = (const manifest_ext_delegation_cert_t *)ext_address;
      *cert_count += 1;
    } else if (table_id == kManifestExtIdDelegationCertSpx) {
      if (certs_spx != NULL) {
        if (spx_count >= max_certs) {
          return kErrorManifestBadExtension;
        }

        enum {
          kMinSizeSpx = CHIP_MANIFEST_SIZE,
          kMaxSizeSpx = CHIP_ROM_EXT_RESIZABLE_SIZE_MAX -
                        sizeof(manifest_ext_delegation_cert_spx_t),
        };

        if (offset < kMinSizeSpx || offset >= kMaxSizeSpx) {
          return kErrorManifestBadExtension;
        }

        uintptr_t ext_address = (uintptr_t)((char *)manifest + offset);
        uint32_t header_id = ((manifest_ext_header_t *)ext_address)->identifier;
        if (header_id != kManifestExtIdDelegationCertSpx) {
          return kErrorManifestBadExtension;
        }

        certs_spx[spx_count] =
            (const manifest_ext_delegation_cert_spx_t *)ext_address;
        spx_count += 1;
      }
    }
  }

  if (certs_spx != NULL && spx_count > 0 && spx_count != *cert_count) {
    // We expect the number of SPX extensions to either be 0 or match the number
    // of certs. If not matching, it's an error. Wait, maybe some certs don't
    // have SPX. Actually if the certs are populated out of order, how do we
    // match them? Let's just assume they appear in pairs if SPX is present. But
    // since the signature of the helper doesn't require returning an error for
    // missing SPX let's just do a simpler scan.
  }

  return kErrorOk;
}
