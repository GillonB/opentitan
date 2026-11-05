// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/lib/sigverify/mldsa_verify.h"

#include <string.h>

#include "sw/device/lib/base/hardened.h"
#include "sw/device/lib/base/hardened_memory.h"
#include "sw/device/silicon_creator/lib/drivers/kmac.h"
#include "sw/device/silicon_creator/lib/drivers/otbn.h"

// OTBN application and symbol declarations matching sw/otbn/crypto/mldsa87
OTBN_DECLARE_APP_SYMBOLS(run_mldsa87);
OTBN_DECLARE_SYMBOL_ADDR(run_mldsa87, mldsa87_mode);
OTBN_DECLARE_SYMBOL_ADDR(run_mldsa87, mldsa87_pk_rho);
OTBN_DECLARE_SYMBOL_ADDR(run_mldsa87, mldsa87_sig_c_tilde);
OTBN_DECLARE_SYMBOL_ADDR(run_mldsa87, mldsa87_mu);
OTBN_DECLARE_SYMBOL_ADDR(run_mldsa87, mldsa87_verify_res_ok);
OTBN_DECLARE_SYMBOL_ADDR(run_mldsa87, mldsa87_verify_res_c_tilde_prime);

static const sc_otbn_app_t kOtbnAppRunMldsa87 =
    OTBN_APP_T_INIT(run_mldsa87);
static const sc_otbn_addr_t kOtbnMldsaMode =
    OTBN_ADDR_T_INIT(run_mldsa87, mldsa87_mode);
static const sc_otbn_addr_t kOtbnMldsaPk =
    OTBN_ADDR_T_INIT(run_mldsa87, mldsa87_pk_rho);
static const sc_otbn_addr_t kOtbnMldsaSig =
    OTBN_ADDR_T_INIT(run_mldsa87, mldsa87_sig_c_tilde);
static const sc_otbn_addr_t kOtbnMldsaMu =
    OTBN_ADDR_T_INIT(run_mldsa87, mldsa87_mu);
static const sc_otbn_addr_t kOtbnMldsaResOk =
    OTBN_ADDR_T_INIT(run_mldsa87, mldsa87_verify_res_ok);
static const sc_otbn_addr_t kOtbnMldsaResCTildePrime =
    OTBN_ADDR_T_INIT(run_mldsa87, mldsa87_verify_res_c_tilde_prime);

enum {
  kMldsa87VerifyMode = 0x1f9b0e52,
};

/*
 * Shares for producing `kSigverifyMldsaSuccess` (0x8d6c8c17) via additive secret sharing:
 *   kMldsaShares[0] ^ ... ^ kMldsaShares[15] == kSigverifyMldsaSuccess.
 */
static const uint32_t kMldsaShares[kMldsa87CTildeWords] = {
    0x39a1f2b4, 0x8c7e01d5, 0x54b3a98e, 0x12f6c07a,
    0x7da4e891, 0x9b20d3f8, 0x4f128c6e, 0x6e5b309a,
    0xa09f7c12, 0x2b8d4e9f, 0xef31048b, 0xd47a96c1,
    0x1c8b3e52, 0x63a921d7, 0x8e5f03ba, 0xf81f2de7,
};

rom_error_t mldsa_compute_mu(const uint32_t *tr,
                             const void *msg_prefix_1,
                             size_t msg_prefix_1_len,
                             const void *msg,
                             size_t msg_len,
                             uint32_t *mu) {
  HARDENED_RETURN_IF_ERROR(kmac_shake256_configure());
  HARDENED_RETURN_IF_ERROR(kmac_shake256_start());

  kmac_shake256_absorb_words(tr, kMldsa87TrWords);

  const uint8_t domain_and_ctx[2] = {0x00, 0x00};
  kmac_shake256_absorb(domain_and_ctx, 2);

  if (msg_prefix_1 != NULL && msg_prefix_1_len > 0) {
    kmac_shake256_absorb((const uint8_t *)msg_prefix_1, msg_prefix_1_len);
  }
  if (msg != NULL && msg_len > 0) {
    kmac_shake256_absorb((const uint8_t *)msg, msg_len);
  }

  kmac_shake256_squeeze_start();
  return kmac_shake256_squeeze_end(mu, kMldsa87MuWords);
}

rom_error_t mldsa_verify_start(const sigverify_mldsa87_key_t *key,
                               const sigverify_mldsa87_signature_t *sig,
                               const uint32_t *mu) {
  // Dynamically load the unified ML-DSA-87 OTBN application
  HARDENED_RETURN_IF_ERROR(sc_otbn_load_app(kOtbnAppRunMldsa87));

  // Set mode to Verify
  uint32_t mode = kMldsa87VerifyMode;
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(1, &mode, kOtbnMldsaMode));

  // Write Public Key (2592 bytes = 648 words)
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(kSigverifyMldsa87PublicKeyWords,
                                              key->data, kOtbnMldsaPk));

  // Note [a]: Signature hint padding byte (index 4627) must be strictly 0x00
  sigverify_mldsa87_signature_t sanitized_sig;
  memcpy(&sanitized_sig, sig, sizeof(sanitized_sig));
  ((uint8_t *)sanitized_sig.data)[kSigverifyMldsa87SigBytes] = 0x00;

  // Write Signature (4628 bytes = 1157 words)
  HARDENED_RETURN_IF_ERROR(sc_otbn_dmem_write(kSigverifyMldsa87SignatureWords,
                                              sanitized_sig.data,
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
    c_tilde_prime[i] ^= sig->data[j] ^ kMldsaShares[i];
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

rom_error_t mldsa_verify(const sigverify_mldsa87_key_t *key,
                         const sigverify_mldsa87_signature_t *sig,
                         const uint32_t *mu,
                         uint32_t *flash_exec) {
  HARDENED_RETURN_IF_ERROR(mldsa_verify_start(key, sig, mu));
  return mldsa_verify_finish(sig, flash_exec);
}
