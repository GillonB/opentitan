// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/lib/sigverify/mldsa_verify.h"

#include <string.h>

#include "sw/device/lib/base/hardened.h"
#include "sw/device/lib/base/hardened_memory.h"
#include "sw/device/silicon_creator/lib/drivers/kmac.h"
#include "sw/device/silicon_creator/lib/drivers/otbn.h"

// OTBN application and symbol declarations matching sw/otbn/crypto/mldsa87/verify
OTBN_DECLARE_APP_SYMBOLS(mldsa87_verify);
OTBN_DECLARE_SYMBOL_ADDR(mldsa87_verify, mldsa87_verify_pk);
OTBN_DECLARE_SYMBOL_ADDR(mldsa87_verify, mldsa87_verify_sig);
OTBN_DECLARE_SYMBOL_ADDR(mldsa87_verify, mldsa87_verify_mu);
OTBN_DECLARE_SYMBOL_ADDR(mldsa87_verify, mldsa87_verify_res_ok);
OTBN_DECLARE_SYMBOL_ADDR(mldsa87_verify, mldsa87_verify_res_c_tilde_prime);

static const sc_otbn_app_t kOtbnAppMldsa87Verify =
    OTBN_APP_T_INIT(mldsa87_verify);
static const sc_otbn_addr_t kOtbnMldsaPk =
    OTBN_ADDR_T_INIT(mldsa87_verify, mldsa87_verify_pk);
static const sc_otbn_addr_t kOtbnMldsaSig =
    OTBN_ADDR_T_INIT(mldsa87_verify, mldsa87_verify_sig);
static const sc_otbn_addr_t kOtbnMldsaMu =
    OTBN_ADDR_T_INIT(mldsa87_verify, mldsa87_verify_mu);
static const sc_otbn_addr_t kOtbnMldsaResOk =
    OTBN_ADDR_T_INIT(mldsa87_verify, mldsa87_verify_res_ok);
static const sc_otbn_addr_t kOtbnMldsaResCTildePrime =
    OTBN_ADDR_T_INIT(mldsa87_verify, mldsa87_verify_res_c_tilde_prime);

/*
 * Shares for producing `kSigverifyMldsaSuccess` (0x8d6c8c17) via additive secret sharing:
 *   kMldsaShares[0] ^ ... ^ kMldsaShares[15] == kSigverifyMldsaSuccess.
 */
static const uint32_t kMldsaShares[kMldsa87CTildeWords] = {
    0x39a1f2b4, 0x8c7e01d5, 0x54b3a98e, 0x12f6c07a,
    0x7da4e891, 0x9b20d3f8, 0x4f128c6e, 0x6e5b309a,
    0xa09f7c12, 0x2b8d4e9f, 0xef31048b, 0xd47a96c1,
    0x1c8b3e52, 0x63a921d7, 0x8e5f03ba, 0x7eacb8fd,
};

// NIST FIPS 204 DER-encoded OID for SHA-384: 2.16.840.1.101.3.4.2.2 (11 bytes)
static const uint8_t kOidSha384[11] = {
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
};

rom_error_t mldsa_compute_mu_prehash(const sigverify_mldsa87_public_key_t *key,
                                     const hmac_digest_sha384_t *msg_digest,
                                     uint32_t *mu) {
  // Step 1: tr = SHAKE256(pk, 64)
  uint32_t tr[kMldsa87TrWords];
  HARDENED_RETURN_IF_ERROR(kmac_shake256_configure());
  HARDENED_RETURN_IF_ERROR(kmac_shake256_start());
  kmac_shake256_absorb_words(key->data, kSigverifyMldsa87PublicKeyWords);
  kmac_shake256_squeeze_start();
  HARDENED_RETURN_IF_ERROR(kmac_shake256_squeeze_end(tr, kMldsa87TrWords));

  // Step 2: M' = 0x01 || 0x00 || OID(SHA-384) || SHA384(msg)
  //   0x01: Pre-hash indicator
  //   0x00: len(ctx) = 0 (empty context for secure boot)
  uint8_t m_prime_header[2] = {0x01, 0x00};

  // Step 3: mu = SHAKE256(tr || M', 64)
  HARDENED_RETURN_IF_ERROR(kmac_shake256_configure());
  HARDENED_RETURN_IF_ERROR(kmac_shake256_start());
  kmac_shake256_absorb_words(tr, kMldsa87TrWords);
  kmac_shake256_absorb(m_prime_header, sizeof(m_prime_header));
  kmac_shake256_absorb(kOidSha384, sizeof(kOidSha384));
  kmac_shake256_absorb_words(msg_digest->digest, kHmacDigestSha384NumWords);
  kmac_shake256_squeeze_start();
  return kmac_shake256_squeeze_end(mu, kMldsa87MuWords);
}

rom_error_t mldsa_verify_start(const sigverify_mldsa87_public_key_t *key,
                               const sigverify_mldsa87_signature_t *sig,
                               const hmac_digest_sha384_t *msg_digest) {
  uint32_t mu[kMldsa87MuWords];
  HARDENED_RETURN_IF_ERROR(mldsa_compute_mu_prehash(key, msg_digest, mu));

  // Dynamically load the OTBN application
  HARDENED_RETURN_IF_ERROR(sc_otbn_load_app(kOtbnAppMldsa87Verify));

  // Write Public Key (2592 bytes = 648 words)
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(kSigverifyMldsa87PublicKeyWords,
                                              key->data, kOtbnMldsaPk));

  // Note [a]: Signature hint padding byte (index 4627) must be strictly 0x00
  sigverify_mldsa87_signature_t sanitized_sig;
  memcpy(&sanitized_sig, sig, sizeof(sanitized_sig));
  sanitized_sig._pad[0] = 0x00;

  // Write Signature (4628 bytes = 1157 words)
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(kSigverifyMldsa87SignatureWords,
                                              (const uint32_t *)&sanitized_sig,
                                              kOtbnMldsaSig));

  // Write mu (64 bytes = 16 words)
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(kMldsa87MuWords, mu,
                                              kOtbnMldsaMu));

  // Execute OTBN verification app
  return sc_otbn_execute_start();
}

rom_error_t mldsa_verify_finish(const sigverify_mldsa87_signature_t *sig,
                                uint32_t *flash_exec) {
  HARDENED_RETURN_IF_ERROR(sc_otbn_busy_wait_for_done());

  // 1. Read OTBN execution result token
  uint32_t ok;
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_read(1, kOtbnMldsaResOk, &ok));

  // 2. Read recomputed challenge c_tilde_prime (16 words)
  uint32_t c_tilde_prime[kMldsa87CTildeWords];
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_read(kMldsa87CTildeWords,
                                             kOtbnMldsaResCTildePrime,
                                             c_tilde_prime));

  // 3. Unconditional secure wipe of OTBN DMEM
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_sec_wipe());

  // 4. Additive Secret Sharing reduction over recovered challenge
  // Step A: c_tilde_prime[i] becomes kMldsaShares[i] if valid, corrupted otherwise
  size_t i = 0;
  for (size_t j = 0; launder32(j) < kMldsa87CTildeWords; ++j, ++i) {
    c_tilde_prime[i] ^= sig->c_tilde[j] ^ kMldsaShares[i];
  }
  HARDENED_CHECK_EQ(i, kMldsa87CTildeWords);

  // Step B: Fold shares into flash_exec_mldsa token
  uint32_t flash_exec_mldsa = 0;
  uint32_t diff = 0;
  for (i = 0; launder32(i) < kMldsa87CTildeWords; ++i) {
    diff |= c_tilde_prime[i] ^ kMldsaShares[i];
    diff |= ~diff + 1;
    diff |= ~(diff >> 31) + 1;
    flash_exec_mldsa ^= c_tilde_prime[i];
    flash_exec_mldsa |= diff;
  }
  HARDENED_CHECK_EQ(i, kMldsa87CTildeWords);

  // 5. Verification validation
  if (launder32(ok) != kMldsa87StatusOk || diff != 0) {
    *flash_exec ^= UINT32_MAX;
    return kErrorSigverifyBadMldsaSignature;
  }
  HARDENED_CHECK_EQ(ok, kMldsa87StatusOk);
  HARDENED_CHECK_EQ(diff, 0);

  *flash_exec ^= flash_exec_mldsa;
  return kErrorOk;
}

rom_error_t mldsa_verify(const sigverify_mldsa87_public_key_t *key,
                         const sigverify_mldsa87_signature_t *sig,
                         const hmac_digest_sha384_t *msg_digest,
                         uint32_t *flash_exec) {
  HARDENED_RETURN_IF_ERROR(mldsa_verify_start(key, sig, msg_digest));
  return mldsa_verify_finish(sig, flash_exec);
}
