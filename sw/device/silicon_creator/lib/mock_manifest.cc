// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/lib/mock_manifest.h"

namespace rom_test {
extern "C" {
rom_error_t manifest_check(const manifest_t *manifest) {
  return MockManifest::Instance().Check(manifest);
}

manifest_digest_region_t manifest_digest_region_get(
    const manifest_t *manifest) {
  return MockManifest::Instance().DigestRegion(manifest);
}

epmp_region_t manifest_code_region_get(const manifest_t *manifest) {
  return MockManifest::Instance().CodeRegion(manifest);
}

uintptr_t manifest_entry_point_get(const manifest_t *manifest) {
  return MockManifest::Instance().EntryPoint(manifest);
}

rom_error_t manifest_ext_get_spx_key(const manifest_t *manifest,
                                     const manifest_ext_spx_key_t **spx_key) {
  return MockManifest::Instance().SpxKey(manifest, spx_key);
}

rom_error_t manifest_ext_get_spx_signature(
    const manifest_t *manifest,
    const manifest_ext_spx_signature_t **spx_signature) {
  return MockManifest::Instance().SpxSignature(manifest, spx_signature);
}

rom_error_t manifest_ext_get_isfb(const manifest_t *manifest,
                                  const manifest_ext_isfb_t **isfb) {
  return MockManifest::Instance().Isfb(manifest, isfb);
}

rom_error_t manifest_ext_get_delegation_cert(
    const manifest_t *manifest,
    const manifest_ext_delegation_cert_t **delegation_cert) {
  return MockManifest::Instance().DelegationCert(manifest, delegation_cert);
}

rom_error_t manifest_ext_get_delegation_certs(
    const manifest_t *manifest, size_t max_certs,
    const manifest_ext_delegation_cert_t *certs[],
    const manifest_ext_delegation_cert_spx_t *certs_spx[], size_t *cert_count) {
  if (MockManifest::Instance().use_delegation_certs) {
    return MockManifest::Instance().DelegationCerts(manifest, max_certs, certs,
                                                    certs_spx, cert_count);
  }
  const manifest_ext_delegation_cert_t *cert = NULL;
  rom_error_t err = MockManifest::Instance().DelegationCert(manifest, &cert);
  if (err == kErrorOk && cert != NULL) {
    certs[0] = cert;
    *cert_count = 1;
    // SPX is optional
    const manifest_ext_delegation_cert_spx_t *spx_cert = NULL;
    rom_error_t spx_err =
        MockManifest::Instance().DelegationCertSpx(manifest, &spx_cert);
    if (spx_err == kErrorOk && spx_cert != NULL && certs_spx != NULL) {
      certs_spx[0] = spx_cert;
    }
    return kErrorOk;
  } else if (err == kErrorManifestBadExtension) {
    *cert_count = 0;
    return kErrorOk;
  } else {
    *cert_count = 0;
    return err;
  }
}

rom_error_t manifest_ext_get_delegation_cert_spx(
    const manifest_t *manifest,
    const manifest_ext_delegation_cert_spx_t **delegation_cert_spx) {
  return MockManifest::Instance().DelegationCertSpx(manifest,
                                                    delegation_cert_spx);
}

}  // extern "C"
}  // namespace rom_test
