#!/usr/bin/env python3
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

"""Signs a BL0 binary with hybrid ECDSA P-256 + ML-DSA-87."""

import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

REPO_ROOT = Path("/usr/local/google/home/bgillon/epic/opentitan")
SCRATCH_DIR = Path("/usr/local/google/home/bgillon/.gemini/jetski/brain/51e3821c-fa7b-4a49-9e3f-cad0b9ab66bb/scratch")
SCRATCH_DIR.mkdir(parents=True, exist_ok=True)

# 1. Load keys
# ML-DSA ACVP51
sk_words = []
pk_words = []
with open(REPO_ROOT / "sw/device/tests/crypto/mldsa87_keygen_testvectors.h") as f:
    in_sk, in_pk = False, False
    for line in f:
        if "kSkNistAcvp51" in line and "{" in line:
            in_sk = True
            continue
        if in_sk:
            if "};" in line:
                in_sk = False
            else:
                for token in line.strip().split(","):
                    t = token.strip()
                    if t.startswith("0x"):
                        sk_words.append(int(t, 16))
        if "kPkNistAcvp51" in line and "{" in line:
            in_pk = True
            continue
        if in_pk:
            if "};" in line:
                in_pk = False
            else:
                for token in line.strip().split(","):
                    t = token.strip()
                    if t.startswith("0x"):
                        pk_words.append(int(t, 16))

assert len(sk_words) == 1224
assert len(pk_words) == 648
pk_bytes = b"".join(w.to_bytes(4, "little") for w in pk_words)
assert len(pk_bytes) == 2592

# Format sk into masked form (1592 words = 6368 bytes)
sk_data = [0] * 1592
sk_data[0:8] = sk_words[0:8]        # RHO
sk_data[8:16] = sk_words[8:16]      # K share 0
sk_data[24:40] = sk_words[16:32]    # TR
sk_data[40:208] = sk_words[32:200]  # S1 share 0
sk_data[376:568] = sk_words[200:392]# S2 share 0
sk_data[760:1592] = sk_words[392:1224] # T0
sk_bytes = b"".join(w.to_bytes(4, "little") for w in sk_data)
sk_hex = "0x" + sk_bytes[::-1].hex()

# 2. Read base BL0 image
in_bin_path = REPO_ROOT / "bazel-bin/sw/device/silicon_creator/rom_ext/e2e/verified_boot/position_owner_slot_a_fpga_cw340_rom_ext.app_prod_0.signed.bin"
with open(in_bin_path, "rb") as f:
    base_data = bytearray(f.read())

# Base length before extensions: 15220 bytes (0x3b74)
# Pad to 64-byte boundary
if len(base_data) % 64 != 0:
    base_data.extend(b"\x00" * (64 - (len(base_data) % 64)))
mldsa_key_offset = len(base_data)
print(f"ML-DSA key offset: {mldsa_key_offset:#010x}")

# ManifestExtKey: header (identifier=0x5a3c9e6b, name=0x32545845) + pk_bytes
key_hdr = struct.pack("<II", 0x5a3c9e6b, 0x32545845)
base_data.extend(key_hdr)
base_data.extend(pk_bytes)

# Pad to 64-byte boundary for signed_region_end
if len(base_data) % 64 != 0:
    base_data.extend(b"\x00" * (64 - (len(base_data) % 64)))
signed_region_end = len(base_data)
print(f"Signed region end: {signed_region_end:#010x}")

mldsa_sig_offset = signed_region_end
print(f"ML-DSA sig offset: {mldsa_sig_offset:#010x}")

# Update manifest fields:
# signed_region_end at offset 828
base_data[828:832] = struct.pack("<I", signed_region_end)

# Extension table entry 5: mldsa_key at 904 + 5*8 = 944
base_data[944:952] = struct.pack("<II", 0x5a3c9e6b, mldsa_key_offset)
# Extension table entry 6: mldsa_signature at 904 + 6*8 = 952
base_data[952:960] = struct.pack("<II", 0x6d9a5b3c, mldsa_sig_offset)

# Set manifest.length BEFORE computing digests, as offset 832 is inside the signed region!
# total_length = signed_region_end + 8 (sig_hdr) + 4628 (sig) = signed_region_end + 4636
unaligned_total = signed_region_end + 8 + 4628
total_length = unaligned_total if unaligned_total % 64 == 0 else unaligned_total + (64 - (unaligned_total % 64))
base_data[832:836] = struct.pack("<I", total_length)
print(f"Predetermined total BL0 length set in manifest: {total_length:#010x} ({total_length} bytes)")

# 3. Compute digests over signed region: [384 .. signed_region_end]
signed_region = bytes(base_data[384:signed_region_end])
act_digest = hashlib.sha256(signed_region).digest()
act_digest_384 = hashlib.sha384(signed_region).digest()
print(f"SHA-256 act_digest: {act_digest.hex()}")
print(f"SHA-384 act_digest_384: {act_digest_384.hex()}")

# 4. Sign with ECDSA P-256
ecdsa_key_path = REPO_ROOT / "sw/device/silicon_creator/lib/ownership/keys/fake/app_prod_ecdsa_p256.der"
with open(ecdsa_key_path, "rb") as f:
    priv_key = load_der_private_key(f.read(), password=None)

sig_der = priv_key.sign(act_digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
r, s = utils.decode_dss_signature(sig_der)
# Store r, s as little-endian 32-byte integers in manifest header (offset 0..64)
base_data[0:32] = r.to_bytes(32, "little")
base_data[32:64] = s.to_bytes(32, "little")
print(f"ECDSA signature written (r={r:#x}, s={s:#x})")

# 5. Sign with ML-DSA-87
# Compute tr = SHAKE256(pk, 64)
tr = hashlib.shake_256(pk_bytes).digest(64)

# Compute M' = 0x01 || 0x00 || OID(SHA-384) || act_digest_384
oid_sha384 = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02])
m_prime = bytes([0x01, 0x00]) + oid_sha384 + act_digest_384
mu = hashlib.shake_256(tr + m_prime).digest(64)
print(f"ML-DSA mu: {mu.hex()}")

# Run otbnsim for mldsa87_sign
mu_hex = "0x" + mu[::-1].hex()
sign_tc = {
    "input": {
        "dmem": {
            "mldsa87_sign_mode": "0x8accea7f",
            "mldsa87_sign_sk": sk_hex,
            "mldsa87_sign_mu": mu_hex,
        }
    }
}
sign_tc_path = SCRATCH_DIR / "bl0_mldsa_sign_tc.hjson"
with open(sign_tc_path, "w") as f:
    json.dump(sign_tc, f)

dmem_out = SCRATCH_DIR / "bl0_dmem_out.bin"
sign_elf = REPO_ROOT / "bazel-bin/sw/otbn/crypto/mldsa87/sign/mldsa87_sign.elf"
standalone_bin = REPO_ROOT / "bazel-out/k8-fastbuild/bin/hw/ip/otbn/dv/otbnsim/standalone"

if dmem_out.exists():
    dmem_out.unlink()
cmd_sign = [
    str(standalone_bin),
    "--testcase", str(sign_tc_path),
    "--dump-dmem", str(dmem_out),
    str(sign_elf),
]
print("Running otbnsim mldsa87_sign...")
res = subprocess.run(cmd_sign, capture_output=True, text=True)
if res.returncode != 0:
    print("Sign FAILED:", res.stderr)
    sys.exit(1)

with open(dmem_out, "rb") as f:
    raw_dmem = f.read()

words = [u32 for vld, u32 in struct.iter_unpack("<BI", raw_dmem)]
flat_dmem = b"".join(w.to_bytes(4, "little") for w in words)

c_tilde = flat_dmem[0x2200:0x2200 + 64]
h = flat_dmem[0x2240:0x2240 + 83]
z = flat_dmem[0x2360:0x2360 + 4480]
mldsa_sig = c_tilde + z + h + b"\x00"
assert len(mldsa_sig) == 4628
print(f"ML-DSA signature loaded (4628 bytes)")

# 6. Append ML-DSA Signature Extension
sig_hdr = struct.pack("<II", 0x6d9a5b3c, 0x33545845)
base_data.extend(sig_hdr)
base_data.extend(mldsa_sig)

# Pad to 64-byte boundary
if len(base_data) % 64 != 0:
    base_data.extend(b"\x00" * (64 - (len(base_data) % 64)))
assert len(base_data) == total_length, f"Expected {total_length}, got {len(base_data)}"
print(f"Total BL0 signed image length verified: {total_length:#010x} ({total_length} bytes)")

# 7. Write hybrid signed BL0
out_bl0_path = SCRATCH_DIR / "boot_test_hybrid_signed.bin"
with open(out_bl0_path, "wb") as f:
    f.write(base_data)
print(f"Wrote hybrid signed BL0 to {out_bl0_path}")

# 8. Verify using mldsa87_verify.elf
pk_rho = pk_bytes[:32]
pk_t1 = pk_bytes[32:]
verify_tc = {
    "input": {
        "dmem": {
            "mldsa87_verify_pk_rho": "0x" + pk_rho[::-1].hex(),
            "mldsa87_verify_pk_t1": "0x" + pk_t1[::-1].hex(),
            "mldsa87_verify_sig_c_tilde": "0x" + c_tilde[::-1].hex(),
            "mldsa87_verify_sig_z": "0x" + z[::-1].hex(),
            "mldsa87_verify_sig_h": "0x" + h[::-1].hex(),
            "mldsa87_verify_mu": "0x" + mu[::-1].hex(),
        }
    }
}
verify_tc_path = SCRATCH_DIR / "bl0_verify_tc.hjson"
with open(verify_tc_path, "w") as f:
    json.dump(verify_tc, f)

verify_dmem_out = SCRATCH_DIR / "bl0_verify_dmem_out.bin"
verify_elf = REPO_ROOT / "bazel-bin/sw/otbn/crypto/mldsa87/verify/mldsa87_verify.elf"
cmd_verify = [
    str(standalone_bin),
    "--testcase", str(verify_tc_path),
    "--dump-dmem", str(verify_dmem_out),
    str(verify_elf),
]
print("Verifying ML-DSA signature on otbnsim...")
res_v = subprocess.run(cmd_verify, capture_output=True, text=True)
if res_v.returncode != 0:
    print("Verify FAILED:", res_v.stderr)
    sys.exit(1)

with open(verify_dmem_out, "rb") as f:
    dmem_v_raw = f.read()

v_words = [u32 for vld, u32 in struct.iter_unpack("<BI", dmem_v_raw)]
res_ok = v_words[0x2500 // 4]
print(f"Verify res_ok: {res_ok:#010x} (expected 0x7baf73d2)")
assert res_ok == 0x7baf73d2, f"Verification failed with code {res_ok:#010x}"
print("VERIFICATION SUCCEEDED!")

# 9. Assemble full 2MB flash image
rom_ext_path = REPO_ROOT / "bazel-bin/sw/device/silicon_creator/rom_ext/rom_ext_dice_x509_slot_a_fpga_cw340.prod_key_0.prod_key_0.signed.bin"
with open(rom_ext_path, "rb") as f:
    rom_ext_data = f.read()

flash_img = bytearray(b"\xff" * 0x200000) # 2MB
flash_img[0:len(rom_ext_data)] = rom_ext_data
flash_img[0x20000:0x20000 + len(base_data)] = base_data

out_flash_path = SCRATCH_DIR / "cw340_flash_hybrid_test.img"
with open(out_flash_path, "wb") as f:
    f.write(flash_img)
print(f"Full flash image created: {out_flash_path} ({len(flash_img)} bytes)")
