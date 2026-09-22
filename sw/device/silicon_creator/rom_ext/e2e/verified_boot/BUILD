# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("//rules:const.bzl", "CONST", "hex")
load(
    "//rules:manifest.bzl",
    "integrator_specific_firmware_binding",
    "manifest",
    "product_expr",
)
load(
    "//rules:otp.bzl",
    "STD_OTP_OVERLAYS",
    "otp_hex",
    "otp_image",
    "otp_json_immutable_rom_ext",
    "otp_partition",
)
load(
    "//sw/device/silicon_creator/rom_ext/imm_section:defs.bzl",
    "IMMUTABLE_HASH_UNENFORCED_MSG",
    "IMM_SECTION_MAJOR_VERSION",
    "IMM_SECTION_MINOR_VERSION",
)
load(
    "//rules/opentitan:defs.bzl",
    "DEFAULT_TEST_FAILURE_MSG",
    "DEFAULT_TEST_SUCCESS_MSG",
    "fpga_params",
    "opentitan_test",
)

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "boot_test",
    srcs = ["boot_test.c"],
)

otp_json_immutable_rom_ext(
    name = "otp_json_with_imm_romext_enabled",
    testonly = True,
    partitions = [
        otp_partition(
            name = "CREATOR_SW_CFG",
            items = {
                "CREATOR_SW_CFG_IMMUTABLE_ROM_EXT_EN": otp_hex(CONST.HARDENED_TRUE),
            },
        ),
    ],
    rom_ext = "//sw/device/silicon_creator/rom_ext:rom_ext_dice_x509_slot_virtual",
    visibility = ["//visibility:private"],
)

otp_image(
    name = "otp_img_with_imm_romext_enabled",
    testonly = True,
    src = "//hw/top_earlgrey/data/otp:otp_json_prod",
    overlays = STD_OTP_OVERLAYS + [
        "//sw/device/silicon_creator/rom_ext/e2e:otp_json_secret2_locked",
        ":otp_json_with_imm_romext_enabled",
    ],
    visibility = ["//visibility:private"],
)

_POSITIONS = {
    "owner_slot_a": {
        "romext": "//sw/device/silicon_creator/rom_ext:rom_ext_dice_x509_slot_a",
        "romext_offset": "{rom_ext_slot_a}",
        "linker_script": "//sw/device/lib/testing/test_framework:ottf_ld_silicon_owner_slot_a",
        "owner_offset": "{owner_slot_a}",
        "success": "bl0_slot = AA__\r\n",
        "otp_img": None,
    },
    "owner_slot_b": {
        "romext": "//sw/device/silicon_creator/rom_ext:rom_ext_dice_x509_slot_a",
        "romext_offset": "{rom_ext_slot_a}",
        "linker_script": "//sw/device/lib/testing/test_framework:ottf_ld_silicon_owner_slot_b",
        "owner_offset": "{owner_slot_b}",
        "success": "bl0_slot = __BB\r\n",
        "otp_img": None,
    },
    "owner_virtual_a": {
        "romext": "//sw/device/silicon_creator/rom_ext:rom_ext_dice_x509_slot_a",
        "romext_offset": "{rom_ext_slot_a}",
        "linker_script": "//sw/device/lib/testing/test_framework:ottf_ld_silicon_owner_slot_virtual",
        "owner_offset": "{owner_slot_a}",
        "success": "bl0_slot = AA__\r\n",
        "otp_img": None,
    },
    "owner_virtual_b": {
        "romext": "//sw/device/silicon_creator/rom_ext:rom_ext_dice_x509_slot_a",
        "romext_offset": "{rom_ext_slot_a}",
        "linker_script": "//sw/device/lib/testing/test_framework:ottf_ld_silicon_owner_slot_virtual",
        "owner_offset": "{owner_slot_b}",
        "success": "bl0_slot = __BB\r\n",
        "otp_img": None,
    },
    "romext_slot_a": {
        "romext": "//sw/device/silicon_creator/rom_ext:rom_ext_dice_x509_slot_a",
        "romext_offset": "{rom_ext_slot_a}",
        "linker_script": "//sw/device/lib/testing/test_framework:ottf_ld_silicon_owner_slot_a",
        "owner_offset": "{owner_slot_a}",
        "success": "rom_ext_slot = AA__\r\n",
        "otp_img": None,
    },
    "romext_slot_b": {
        "romext": "//sw/device/silicon_creator/rom_ext:rom_ext_dice_x509_slot_b",
        "romext_offset": "{rom_ext_slot_b}",
        "linker_script": "//sw/device/lib/testing/test_framework:ottf_ld_silicon_owner_slot_a",
        "owner_offset": "{owner_slot_a}",
        "success": "rom_ext_slot = __BB\r\n",
        "otp_img": None,
    },
    "romext_virtual_a": {
        "romext": "//sw/device/silicon_creator/rom_ext:rom_ext_dice_x509_slot_virtual",
        "romext_offset": "{rom_ext_slot_a}",
        "linker_script": "//sw/device/lib/testing/test_framework:ottf_ld_silicon_owner_slot_a",
        "owner_offset": "{owner_slot_a}",
        "success": "rom_ext_slot = AA__\r\n",
        "otp_img": None,
    },
    "romext_virtual_b": {
        "romext": "//sw/device/silicon_creator/rom_ext:rom_ext_dice_x509_slot_virtual",
        "romext_offset": "{rom_ext_slot_b}",
        "linker_script": "//sw/device/lib/testing/test_framework:ottf_ld_silicon_owner_slot_a",
        "owner_offset": "{owner_slot_a}",
        "success": "rom_ext_slot = __BB\r\n",
        "otp_img": None,
    },
    "romext_virtual_a_with_imm_romext_enabled": {
        "romext": "//sw/device/silicon_creator/rom_ext:rom_ext_dice_x509_slot_virtual",
        "romext_offset": "{rom_ext_slot_a}",
        "linker_script": "//sw/device/lib/testing/test_framework:ottf_ld_silicon_owner_slot_a",
        "owner_offset": "{owner_slot_a}",
        "success": "rom_ext_slot = AA__\r\n",
        "failure": IMMUTABLE_HASH_UNENFORCED_MSG,
        "otp_img": ":otp_img_with_imm_romext_enabled",
    },
    "imm_section_virtual_a": {
        "romext": "//sw/device/silicon_creator/rom_ext:rom_ext_dice_x509_slot_virtual",
        "romext_offset": "{rom_ext_slot_a}",
        "linker_script": "//sw/device/lib/testing/test_framework:ottf_ld_silicon_owner_slot_a",
        "owner_offset": "{owner_slot_a}",
        "success": "IMM_SECTION:{}.{}".format(IMM_SECTION_MAJOR_VERSION, IMM_SECTION_MINOR_VERSION),
        "otp_img": None,
    },
}

[
    opentitan_test(
        name = "position_{}".format(name),
        srcs = [":boot_test"],
        exec_env = {
            "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
        },
        fpga = fpga_params(
            assemble = "{romext}@{romext_offset} {firmware}@{owner_offset}",
            binaries = {
                position["romext"]: "romext",
            },
            exit_failure = position.get("failure", DEFAULT_TEST_FAILURE_MSG),
            exit_success = position["success"],
            otp = position["otp_img"],
            owner_offset = position["owner_offset"],
            romext_offset = position["romext_offset"],
        ),
        linker_script = position["linker_script"],
        deps = [
            "//sw/device/lib/base:status",
            "//sw/device/lib/testing/test_framework:ottf_main",
            "//sw/device/silicon_creator/lib:boot_log",
            "//sw/device/silicon_creator/lib/drivers:retention_sram",
        ],
    )
    for name, position in _POSITIONS.items()
]

test_suite(
    name = "positions",
    tests = ["position_{}".format(name) for name in _POSITIONS],
)

manifest(d = {
    "name": "bad_manifest",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "manifest_version_major": "0",
    "manifest_version_minor": "0",
    "visibility": ["//visibility:public"],
})

opentitan_test(
    name = "bad_manifest_test",
    srcs = [":boot_test"],
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        exit_failure = "PASS|FAIL|FAULT|BFV:.{8}",
        # Because our bad manifest has an invalid manifest version, we should
        # expect kErrorManifestBadVersionMajor from the ROM_EXT.
        exit_success = "BFV:054d410d",
    ),
    manifest = ":bad_manifest",
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

manifest(d = {
    "name": "bad_spx_manifest",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "visibility": ["//visibility:public"],
    "extensions": [
        "spx_key",
        "",
        "secver_write",
        "isfb",
        "isfb_erase",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "spx_signature",
    ],
})

opentitan_test(
    name = "bad_spx_manifest_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        exit_failure = "PASS|FAIL|FAULT|BFV:.{8}",
        # Because our bad manifest placed spx_signature in a wrong slot, we
        # should expect kErrorManifestBadExtension from the ROM_EXT.
        exit_success = "BFV:044d410d",
    ),
    manifest = ":bad_spx_manifest",
    spx_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:spx_keyset": "app_prod_0"},
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

_KEYS = {
    "dev": {
        "ecdsa": {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_dev_0"},
        "spx": {},
        "exit_success": DEFAULT_TEST_SUCCESS_MSG,
        "exit_failure": DEFAULT_TEST_FAILURE_MSG,
    },
    "dev_hybrid_spx_prehashed": {
        "ecdsa": {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_dev_0"},
        "spx": {"//sw/device/silicon_creator/lib/ownership/keys/fake:spx_keyset": "app_dev_0"},
        "exit_success": DEFAULT_TEST_SUCCESS_MSG,
        "exit_failure": DEFAULT_TEST_FAILURE_MSG,
    },
    "prod": {
        "ecdsa": {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
        "spx": {},
        "exit_success": DEFAULT_TEST_SUCCESS_MSG,
        "exit_failure": DEFAULT_TEST_FAILURE_MSG,
    },
    "prod_hybrid_spx_pure": {
        "ecdsa": {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
        "spx": {"//sw/device/silicon_creator/lib/ownership/keys/fake:spx_keyset": "app_prod_0"},
        "exit_success": DEFAULT_TEST_SUCCESS_MSG,
        "exit_failure": DEFAULT_TEST_FAILURE_MSG,
    },
    "test": {
        "ecdsa": {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_test_0"},
        "spx": {},
        "exit_success": DEFAULT_TEST_SUCCESS_MSG,
        "exit_failure": DEFAULT_TEST_FAILURE_MSG,
    },
    "unauthorized": {
        "ecdsa": {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_unauthorized_0"},
        "spx": {},
        "exit_success": DEFAULT_TEST_FAILURE_MSG,
        "exit_failure": DEFAULT_TEST_SUCCESS_MSG,
    },
}

[
    opentitan_test(
        name = "key_{}".format(name),
        srcs = [":boot_test"],
        ecdsa_key = keyinfo["ecdsa"],
        exec_env = {
            "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
        },
        fpga = fpga_params(
            exit_failure = keyinfo["exit_failure"],
            exit_success = keyinfo["exit_success"],
        ),
        spx_key = keyinfo["spx"],
        deps = [
            "//sw/device/lib/base:status",
            "//sw/device/lib/testing/test_framework:ottf_main",
            "//sw/device/silicon_creator/lib:boot_log",
            "//sw/device/silicon_creator/lib/drivers:retention_sram",
        ],
    )
    for name, keyinfo in _KEYS.items()
]

test_suite(
    name = "keys",
    tests = ["key_{}".format(name) for name in _KEYS],
)

manifest(d = {
    "name": "isfb_manifest",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "visibility": ["//visibility:public"],
    "integrator_specific_firmware_binding": integrator_specific_firmware_binding(
        name = "isfb",
        product_exprs = [
            product_expr(
                name = "none",
                mask = "0xFFFFFFFF",
                value = "0xFFFFFFFF",
            ),
        ],
        strike_mask = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    ),
})

opentitan_test(
    name = "isfb_boot_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(),
    manifest = ":isfb_manifest",
    spx_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:spx_keyset": "app_prod_0"},
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

manifest(d = {
    "name": "delegation_manifest",
    "security_version": "0x1",
    "delegate_public_key": "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "visibility": ["//visibility:public"],
    "extensions": [
        "",
        "",
        "secver_write",
        "isfb",
        "isfb_erase",
        "delegation_cert",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ],
    "delegation_cert": json.encode({
        "version": 1,
        "owner_key_id": 0x265b676b,
        "delegate_key_alg": 0x36353250,
        "delegate_public_key": {
            "x": [107, 103, 91, 38, 31, 241, 109, 101, 36, 140, 38, 231, 113, 43, 104, 247, 188, 7, 84, 26, 139, 79, 214, 96, 234, 240, 243, 13, 192, 130, 222, 50],
            "y": [176, 7, 129, 36, 100, 19, 223, 221, 88, 29, 155, 169, 51, 115, 137, 53, 218, 36, 19, 102, 212, 207, 217, 74, 72, 202, 85, 172, 244, 86, 212, 71],
        },
        "min_security_version": 1,
        "max_security_version": 10,
        "allowed_slots": 3,
        "expiration_epoch": 12345678,
        "usage_constraint": 0,
        "device_id": [1, 2, 3, 4, 5, 6, 7, 8],
        "manuf_state_creator": 0,
        "manuf_state_owner": 0,
        "life_cycle_state": 4294967295,
        "owner_signature": None,
    }),
})

opentitan_test(
    name = "delegation_boot_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        testopt_clear_before_test = "True",
    ),
    manifest = ":delegation_manifest",
    data = [
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    ],
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

manifest(d = {
    "name": "delegation_tier2_manifest",
    "security_version": "0x1",
    "delegate_public_key": "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "visibility": ["//visibility:public"],
    "extensions": [
        "",
        "",
        "secver_write",
        "isfb",
        "isfb_erase",
        "delegation_cert",
        "delegation_cert",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ],
    "delegation_certs": [
        json.encode({
            "cert_type": 0x494e5452,
            "version": 1,
            "owner_key_id": 0x265b676b,
            "delegate_key_alg": 0x36353250,
            "delegate_public_key": {
                "x": [107, 103, 91, 38, 31, 241, 109, 101, 36, 140, 38, 231, 113, 43, 104, 247, 188, 7, 84, 26, 139, 79, 214, 96, 234, 240, 243, 13, 192, 130, 222, 50],
                "y": [176, 7, 129, 36, 100, 19, 223, 221, 88, 29, 155, 169, 51, 115, 137, 53, 218, 36, 19, 102, 212, 207, 217, 74, 72, 202, 85, 172, 244, 86, 212, 71],
            },
            "min_security_version": 1,
            "max_security_version": 10,
            "allowed_slots": 3,
            "expiration_epoch": 12345678,
            "usage_constraint": 0,
            "device_id": [1, 2, 3, 4, 5, 6, 7, 8],
            "manuf_state_creator": 0,
            "manuf_state_owner": 0,
            "life_cycle_state": 4294967295,
            "owner_signature": None,
        }),
        json.encode({
            "cert_type": 0x4c454146,
            "version": 1,
            "owner_key_id": 0x265b676b,
            "delegate_key_alg": 0x36353250,
            "delegate_public_key": {
                "x": [107, 103, 91, 38, 31, 241, 109, 101, 36, 140, 38, 231, 113, 43, 104, 247, 188, 7, 84, 26, 139, 79, 214, 96, 234, 240, 243, 13, 192, 130, 222, 50],
                "y": [176, 7, 129, 36, 100, 19, 223, 221, 88, 29, 155, 169, 51, 115, 137, 53, 218, 36, 19, 102, 212, 207, 217, 74, 72, 202, 85, 172, 244, 86, 212, 71],
            },
            "min_security_version": 1,
            "max_security_version": 10,
            "allowed_slots": 3,
            "expiration_epoch": 12345678,
            "usage_constraint": 0,
            "device_id": [1, 2, 3, 4, 5, 6, 7, 8],
            "manuf_state_creator": 0,
            "manuf_state_owner": 0,
            "life_cycle_state": 4294967295,
            "owner_signature": None,
        }),
    ],
})

opentitan_test(
    name = "delegation_tier2_boot_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        testopt_clear_before_test = "True",
    ),
    manifest = ":delegation_tier2_manifest",
    data = [
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    ],
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

manifest(d = {
    "name": "delegation_restricted_attestation_manifest",
    "security_version": "0x1",
    "delegate_public_key": "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "visibility": ["//visibility:public"],
    "extensions": [
        "",
        "",
        "secver_write",
        "isfb",
        "isfb_erase",
        "delegation_cert",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ],
    "delegation_cert": json.encode({
        "version": 1,
        "owner_key_id": 0x265b676b,
        "delegate_key_alg": 0x36353250,
        "delegate_public_key": {
            "x": [107, 103, 91, 38, 31, 241, 109, 101, 36, 140, 38, 231, 113, 43, 104, 247, 188, 7, 84, 26, 139, 79, 214, 96, 234, 240, 243, 13, 192, 130, 222, 50],
            "y": [176, 7, 129, 36, 100, 19, 223, 221, 88, 29, 155, 169, 51, 115, 137, 53, 218, 36, 19, 102, 212, 207, 217, 74, 72, 202, 85, 172, 244, 86, 212, 71],
        },
        "min_security_version": 1,
        "max_security_version": 10,
        "allowed_slots": 3,
        "expiration_epoch": 12345678,
        "usage_constraint": 16384, # Bit 14 (restricted attestation)
        "device_id": [1, 2, 3, 4, 5, 6, 7, 8],
        "manuf_state_creator": 0,
        "manuf_state_owner": 0,
        "life_cycle_state": 4294967295,
        "owner_signature": None
    }),
})

opentitan_test(
    name = "delegation_restricted_attestation_boot_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        testopt_clear_before_test = "True",
    ),
    manifest = ":delegation_restricted_attestation_manifest",
    data = [
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    ],
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

manifest(d = {
    "name": "delegation_secver_reject_manifest",
    "security_version": "0x1",
    "delegate_public_key": "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "visibility": ["//visibility:public"],
    "extensions": [
        "",
        "",
        "secver_write",
        "isfb",
        "isfb_erase",
        "delegation_cert",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ],
    "delegation_cert": json.encode({
        "version": 1,
        "owner_key_id": 0x265b676b,
        "delegate_key_alg": 0x36353250,
        "delegate_public_key": {
            "x": [107, 103, 91, 38, 31, 241, 109, 101, 36, 140, 38, 231, 113, 43, 104, 247, 188, 7, 84, 26, 139, 79, 214, 96, 234, 240, 243, 13, 192, 130, 222, 50],
            "y": [176, 7, 129, 36, 100, 19, 223, 221, 88, 29, 155, 169, 51, 115, 137, 53, 218, 36, 19, 102, 212, 207, 217, 74, 72, 202, 85, 172, 244, 86, 212, 71],
        },
        "min_security_version": 5, # Requires min SV 5, but manifest is 1
        "max_security_version": 10,
        "allowed_slots": 3,
        "expiration_epoch": 12345678,
        "usage_constraint": 0,
        "device_id": [1, 2, 3, 4, 5, 6, 7, 8],
        "manuf_state_creator": 0,
        "manuf_state_owner": 0,
        "life_cycle_state": 4294967295,
        "owner_signature": None
    }),
})

opentitan_test(
    name = "delegation_secver_reject_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        exit_failure = "PASS|bl0_slot",
        exit_success = "BFV:.{8}",
        testopt_clear_before_test = "True",
    ),
    manifest = ":delegation_secver_reject_manifest",
    data = [
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    ],
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

manifest(d = {
    "name": "delegation_hybrid_spx_pure_manifest",
    "security_version": "0x1",
    "delegate_public_key": "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "visibility": ["//visibility:public"],
    "extensions": [
        "spx_key",
        "spx_signature",
        "secver_write",
        "isfb",
        "isfb_erase",
        "delegation_cert",
        "delegation_cert_spx",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ],
    "delegation_cert": json.encode({
        "version": 1,
        "owner_key_id": 0x323ced4c,
        "delegate_key_alg": 0x75502b48,
        "delegate_public_key": {
            "x": [107, 103, 91, 38, 31, 241, 109, 101, 36, 140, 38, 231, 113, 43, 104, 247, 188, 7, 84, 26, 139, 79, 214, 96, 234, 240, 243, 13, 192, 130, 222, 50],
            "y": [176, 7, 129, 36, 100, 19, 223, 221, 88, 29, 155, 169, 51, 115, 137, 53, 218, 36, 19, 102, 212, 207, 217, 74, 72, 202, 85, 172, 244, 86, 212, 71],
        },
        "min_security_version": 1,
        "max_security_version": 10,
        "allowed_slots": 3,
        "expiration_epoch": 12345678,
        "usage_constraint": 0,
        "device_id": [1, 2, 3, 4, 5, 6, 7, 8],
        "manuf_state_creator": 0,
        "manuf_state_owner": 0,
        "life_cycle_state": 4294967295,
        "owner_signature": None,
    }),
    "delegation_cert_spx": json.encode({
        "delegate_spx_key": [39, 138, 103, 20, 23, 151, 253, 119, 55, 86, 243, 136, 168, 190, 23, 197, 211, 61, 17, 123, 226, 226, 185, 92, 8, 92, 31, 66, 234, 238, 228, 198],
        "signature": None,
    }),
})

opentitan_test(
    name = "delegation_hybrid_spx_pure_boot_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    spx_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:spx_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        testopt_clear_before_test = "True",
    ),
    manifest = ":delegation_hybrid_spx_pure_manifest",
    data = [
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_spx.pub.pem",
    ],
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

manifest(d = {
    "name": "delegation_hybrid_spx_prehash_manifest",
    "security_version": "0x1",
    "delegate_public_key": "//sw/device/silicon_creator/lib/ownership/keys/fake:app_dev_ecdsa_p256.pub.der",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "visibility": ["//visibility:public"],
    "extensions": [
        "spx_key",
        "spx_signature",
        "secver_write",
        "isfb",
        "isfb_erase",
        "delegation_cert",
        "delegation_cert_spx",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ],
    "delegation_cert": json.encode({
        "version": 1,
        "owner_key_id": 0x40c246ad,
        "delegate_key_alg": 0x32532b48,
        "delegate_public_key": {
            "x": [12, 58, 212, 221, 238, 101, 34, 98, 212, 102, 91, 174, 202, 107, 192, 148, 174, 147, 4, 49, 30, 246, 246, 78, 63, 129, 129, 117, 249, 47, 123, 172],
            "y": [82, 59, 170, 197, 81, 28, 219, 7, 220, 72, 81, 144, 222, 88, 196, 229, 75, 254, 204, 235, 68, 87, 126, 49, 253, 118, 62, 134, 144, 26, 143, 160],
        },
        "min_security_version": 1,
        "max_security_version": 10,
        "allowed_slots": 3,
        "expiration_epoch": 12345678,
        "usage_constraint": 0,
        "device_id": [1, 2, 3, 4, 5, 6, 7, 8],
        "manuf_state_creator": 0,
        "manuf_state_owner": 0,
        "life_cycle_state": 4294967295,
        "owner_signature": None,
    }),
    "delegation_cert_spx": json.encode({
        "delegate_spx_key": [161, 164, 22, 157, 176, 174, 113, 184, 202, 15, 69, 65, 197, 231, 43, 52, 124, 217, 230, 71, 205, 126, 221, 151, 6, 169, 33, 21, 123, 76, 162, 11],
        "signature": None,
    }),
})

opentitan_test(
    name = "delegation_hybrid_spx_prehash_boot_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_dev_0"},
    spx_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:spx_keyset": "app_dev_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        testopt_clear_before_test = "True",
    ),
    manifest = ":delegation_hybrid_spx_prehash_manifest",
    data = [
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_dev_ecdsa_p256.pub.der",
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_dev_spx.pub.pem",
    ],
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

opentitan_test(
    name = "disable_direct_boot_reject_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        assemble = "{romext}@{romext_offset} {firmware}@{owner_offset}",
        binaries = {
            "//sw/device/silicon_creator/rom_ext:rom_ext_disable_direct_boot": "romext",
        },
        exit_failure = "PASS|bl0_slot",
        exit_success = "BFV:034f5703",
        owner_offset = "{owner_slot_a}",
        romext_offset = "{rom_ext_slot_a}",
        testopt_clear_before_test = "True",
    ),
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

opentitan_test(
    name = "disable_direct_boot_delegation_success_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        assemble = "{romext}@{romext_offset} {firmware}@{owner_offset}",
        binaries = {
            "//sw/device/silicon_creator/rom_ext:rom_ext_disable_direct_boot": "romext",
        },
        owner_offset = "{owner_slot_a}",
        romext_offset = "{rom_ext_slot_a}",
        testopt_clear_before_test = "True",
    ),
    manifest = ":delegation_manifest",
    data = [
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    ],
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

manifest(d = {
    "name": "delegation_max_secver_reject_manifest",
    "security_version": "0xC", # SV 12 > Max SV 10
    "delegate_public_key": "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "visibility": ["//visibility:public"],
    "extensions": [
        "",
        "",
        "secver_write",
        "isfb",
        "isfb_erase",
        "delegation_cert",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ],
    "delegation_cert": json.encode({
        "version": 1,
        "owner_key_id": 0x265b676b,
        "delegate_key_alg": 0x36353250,
        "delegate_public_key": {
            "x": [107, 103, 91, 38, 31, 241, 109, 101, 36, 140, 38, 231, 113, 43, 104, 247, 188, 7, 84, 26, 139, 79, 214, 96, 234, 240, 243, 13, 192, 130, 222, 50],
            "y": [176, 7, 129, 36, 100, 19, 223, 221, 88, 29, 155, 169, 51, 115, 137, 53, 218, 36, 19, 102, 212, 207, 217, 74, 72, 202, 85, 172, 244, 86, 212, 71],
        },
        "min_security_version": 1,
        "max_security_version": 10,
        "allowed_slots": 3,
        "expiration_epoch": 12345678,
        "usage_constraint": 0,
        "device_id": [1, 2, 3, 4, 5, 6, 7, 8],
        "manuf_state_creator": 0,
        "manuf_state_owner": 0,
        "life_cycle_state": 4294967295,
        "owner_signature": None,
    }),
})

opentitan_test(
    name = "delegation_max_secver_reject_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        exit_failure = "PASS|bl0_slot",
        exit_success = "BFV:154f5703",
        testopt_clear_before_test = "True",
    ),
    manifest = ":delegation_max_secver_reject_manifest",
    data = [
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    ],
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

manifest(d = {
    "name": "delegation_slot_mismatch_reject_manifest",
    "security_version": "0x1",
    "delegate_public_key": "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "visibility": ["//visibility:public"],
    "extensions": [
        "",
        "",
        "secver_write",
        "isfb",
        "isfb_erase",
        "delegation_cert",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ],
    "delegation_cert": json.encode({
        "version": 1,
        "owner_key_id": 0x265b676b,
        "delegate_key_alg": 0x36353250,
        "delegate_public_key": {
            "x": [107, 103, 91, 38, 31, 241, 109, 101, 36, 140, 38, 231, 113, 43, 104, 247, 188, 7, 84, 26, 139, 79, 214, 96, 234, 240, 243, 13, 192, 130, 222, 50],
            "y": [176, 7, 129, 36, 100, 19, 223, 221, 88, 29, 155, 169, 51, 115, 137, 53, 218, 36, 19, 102, 212, 207, 217, 74, 72, 202, 85, 172, 244, 86, 212, 71],
        },
        "min_security_version": 1,
        "max_security_version": 10,
        "allowed_slots": 2, # Slot B only (bit 1=1, bit 0=0)
        "expiration_epoch": 12345678,
        "usage_constraint": 0,
        "device_id": [1, 2, 3, 4, 5, 6, 7, 8],
        "manuf_state_creator": 0,
        "manuf_state_owner": 0,
        "life_cycle_state": 4294967295,
        "owner_signature": None,
    }),
})

opentitan_test(
    name = "delegation_slot_mismatch_reject_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        exit_failure = "PASS|bl0_slot",
        exit_success = "BFV:164f5703",
        testopt_clear_before_test = "True",
    ),
    manifest = ":delegation_slot_mismatch_reject_manifest",
    data = [
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    ],
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

manifest(d = {
    "name": "delegation_device_id_reject_manifest",
    "security_version": "0x1",
    "delegate_public_key": "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "visibility": ["//visibility:public"],
    "extensions": [
        "",
        "",
        "secver_write",
        "isfb",
        "isfb_erase",
        "delegation_cert",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ],
    "delegation_cert": json.encode({
        "version": 1,
        "owner_key_id": 0x265b676b,
        "delegate_key_alg": 0x36353250,
        "delegate_public_key": {
            "x": [107, 103, 91, 38, 31, 241, 109, 101, 36, 140, 38, 231, 113, 43, 104, 247, 188, 7, 84, 26, 139, 79, 214, 96, 234, 240, 243, 13, 192, 130, 222, 50],
            "y": [176, 7, 129, 36, 100, 19, 223, 221, 88, 29, 155, 169, 51, 115, 137, 53, 218, 36, 19, 102, 212, 207, 217, 74, 72, 202, 85, 172, 244, 86, 212, 71],
        },
        "min_security_version": 1,
        "max_security_version": 10,
        "allowed_slots": 3,
        "expiration_epoch": 12345678,
        "usage_constraint": 1, # Bit 0: Check Device ID word 0
        "device_id": [0xDEADBEEF, 2, 3, 4, 5, 6, 7, 8],
        "manuf_state_creator": 0,
        "manuf_state_owner": 0,
        "life_cycle_state": 4294967295,
        "owner_signature": None,
    }),
})

opentitan_test(
    name = "delegation_device_id_reject_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        exit_failure = "PASS|bl0_slot",
        exit_success = "BFV:174f5703",
        testopt_clear_before_test = "True",
    ),
    manifest = ":delegation_device_id_reject_manifest",
    data = [
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    ],
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)

manifest(d = {
    "name": "delegation_lifecycle_reject_manifest",
    "security_version": "0x1",
    "delegate_public_key": "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    "address_translation": hex(CONST.HARDENED_FALSE),
    "identifier": hex(CONST.OWNER),
    "visibility": ["//visibility:public"],
    "extensions": [
        "",
        "",
        "secver_write",
        "isfb",
        "isfb_erase",
        "delegation_cert",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ],
    "delegation_cert": json.encode({
        "version": 1,
        "owner_key_id": 0x265b676b,
        "delegate_key_alg": 0x36353250,
        "delegate_public_key": {
            "x": [107, 103, 91, 38, 31, 241, 109, 101, 36, 140, 38, 231, 113, 43, 104, 247, 188, 7, 84, 26, 139, 79, 214, 96, 234, 240, 243, 13, 192, 130, 222, 50],
            "y": [176, 7, 129, 36, 100, 19, 223, 221, 88, 29, 155, 169, 51, 115, 137, 53, 218, 36, 19, 102, 212, 207, 217, 74, 72, 202, 85, 172, 244, 86, 212, 71],
        },
        "min_security_version": 1,
        "max_security_version": 10,
        "allowed_slots": 3,
        "expiration_epoch": 12345678,
        "usage_constraint": 1024, # Bit 10: Check Lifecycle State
        "device_id": [1, 2, 3, 4, 5, 6, 7, 8],
        "manuf_state_creator": 0,
        "manuf_state_owner": 0,
        "life_cycle_state": 2, # Dev only (Bit 1=1), but chip is Prod (Bit 2=1)
        "owner_signature": None,
    }),
})

opentitan_test(
    name = "delegation_lifecycle_reject_test",
    srcs = [":boot_test"],
    ecdsa_key = {"//sw/device/silicon_creator/lib/ownership/keys/fake:ecdsa_keyset": "app_prod_0"},
    exec_env = {
        "//hw/top_earlgrey:fpga_cw340_rom_ext": None,
    },
    fpga = fpga_params(
        exit_failure = "PASS|bl0_slot",
        exit_success = "BFV:1a4f5703",
        testopt_clear_before_test = "True",
    ),
    manifest = ":delegation_lifecycle_reject_manifest",
    data = [
        "//sw/device/silicon_creator/lib/ownership/keys/fake:app_prod_ecdsa_p256.pub.der",
    ],
    deps = [
        "//sw/device/lib/base:status",
        "//sw/device/lib/testing/test_framework:ottf_main",
        "//sw/device/silicon_creator/lib:boot_log",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
    ],
)






