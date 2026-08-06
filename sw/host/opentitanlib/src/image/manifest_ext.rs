// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use serde::{self, Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

use crate::chip::boolean::HardenedBool;
use crate::crypto::ecdsa::{EcdsaPublicKey, EcdsaRawPublicKey, EcdsaRawSignature};
use crate::image::manifest::*;
use crate::image::manifest_def::le_bytes_to_word_arr;
use crate::util::num_de::HexEncoded;
use crate::with_unknown;
use sphincsplus::{DecodeKey, SpxPublicKey, SphincsPlus};

#[derive(Debug, Error)]
pub enum ManifestExtError {
    #[error("Extension ID 0x{0:x} has duplicate extension data.")]
    DuplicateEntry(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathOrRaw<T> {
    Path(PathBuf),
    Raw(T),
}

impl<T: Serialize> Serialize for PathOrRaw<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            PathOrRaw::Path(path) => path.serialize(serializer),
            PathOrRaw::Raw(raw) => raw.serialize(serializer),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for PathOrRaw<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Helper<T> {
            Path(PathBuf),
            Raw(T),
        }
        match Helper::deserialize(deserializer)? {
            Helper::Path(path) => Ok(PathOrRaw::Path(path)),
            Helper::Raw(raw) => Ok(PathOrRaw::Raw(raw)),
        }
    }
}

with_unknown! {
    /// Known manifest extension variant IDs.
    #[derive(Default)]
    pub enum ManifestExtId: u32 {
        spx_key = MANIFEST_EXT_ID_SPX_KEY,
        spx_signature = MANIFEST_EXT_ID_SPX_SIGNATURE,
        image_type = MANIFEST_EXT_ID_IMAGE_TYPE,
        secver_write = MANIFEST_EXT_ID_SECVER_WRITE,
        isfb = MANIFEST_EXT_ID_ISFB,
        isfb_erase = MANIFEST_EXT_ID_ISFB_ERASE,
        delegation_cert = MANIFEST_EXT_ID_DELEGATION_CERT,
        delegation_cert_spx = MANIFEST_EXT_ID_DELEGATION_CERT_SPX,
    }
}

/// Top level spec for manifest extension HJSON files.
#[derive(Default, Debug, Deserialize, Serialize)]
pub struct ManifestExtSpec {
    pub extension_params: Vec<ManifestExtEntrySpec>,
    #[serde(skip)]
    relative_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ProductExpr {
    pub mask: HexEncoded<u32>,
    pub value: HexEncoded<u32>,
}

/// Specs for the known extension variants.
///
/// This includes a raw variant that can take any id, name, and value.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum ManifestExtEntrySpec {
    #[serde(alias = "spx_key")]
    SpxKey {
        /// The path to the SPHINCS+ public or private key.
        spx_key: PathBuf,
    },
    #[serde(alias = "spx_signature")]
    SpxSignature {
        /// The path to the SPHINCS+ signature.
        spx_signature: PathBuf,
    },

    #[serde(alias = "image_type")]
    ImageType { image_type: u32 },

    #[serde(alias = "secver_write")]
    SecVerWrite {
        /// Whether or not to write the security version into boot data.
        secver_write: bool,
    },

    #[serde(alias = "integrator_specific_firmware_binding")]
    Isfb {
        strike_mask: HexEncoded<u128>,
        product_expr: Vec<ProductExpr>,
    },

    #[serde(alias = "isfb_erase_policy")]
    IsfbErasePolicy { erase_allowed: bool },

    #[serde(alias = "delegation_cert")]
    DelegationCert {
        version: u32,
        owner_key_id: u32,
        delegate_key_alg: u32,
        delegate_public_key: PathOrRaw<EcdsaRawPublicKey>,
        min_security_version: u32,
        max_security_version: u32,
        allowed_slots: u32,
        expiration_epoch: u64,
        usage_constraint: u32,
        device_id: [u32; 8],
        manuf_state_creator: u32,
        manuf_state_owner: u32,
        life_cycle_state: u32,
        owner_signature: Option<PathOrRaw<EcdsaRawSignature>>,
    },

    #[serde(alias = "delegation_cert_spx")]
    DelegationCertSpx {
        delegate_spx_key: PathOrRaw<Vec<u8>>,
        signature: Option<PathOrRaw<Vec<u8>>>,
    },

    #[serde(alias = "raw")]
    Raw {
        name: HexEncoded<u32>,
        identifier: HexEncoded<u32>,
        signed: bool,
        value: Vec<HexEncoded<u8>>,
    },
}

#[derive(Debug)]
pub enum ManifestExtEntry {
    SpxKey(ManifestExtSpxKey),
    SpxSignature(Box<ManifestExtSpxSignature>),
    ImageType(ManifestExtImageType),
    SecVerWrite(ManifestExtSecVerWrite),
    Isfb(ManifestExtIsfb),
    IsfbErasePolicy(ManifestExtIsfbErasePolicy),
    DelegationCert(Box<ManifestExtDelegationCert>),
    DelegationCertSpx(Box<ManifestExtDelegationCertSpx>),
    Raw {
        header: ManifestExtHeader,
        data: Vec<u8>,
    },
}

impl ManifestExtSpec {
    /// Reads in a `ManifestExtSpec` from an HJSON file.
    ///
    /// The parent of `path` (the directory containing the HJSON file to be loaded) is used when
    /// resolving relative paths for any extension data that references a file.
    pub fn read_from_file(path: &Path) -> Result<Self> {
        let mut spec: Self = deser_hjson::from_str(&std::fs::read_to_string(path)?)?;
        spec.relative_path = path.parent().map(|v| v.to_owned());
        Ok(spec)
    }

    /// The partent of the path that was provided when loading this spec.
    pub fn source_path(&self) -> Option<&Path> {
        self.relative_path.as_deref()
    }
}

impl ManifestExtEntrySpec {
    pub fn id(&self) -> u32 {
        match self {
            ManifestExtEntrySpec::SpxKey { spx_key: _ } => MANIFEST_EXT_ID_SPX_KEY,
            ManifestExtEntrySpec::SpxSignature { spx_signature: _ } => {
                MANIFEST_EXT_ID_SPX_SIGNATURE
            }
            ManifestExtEntrySpec::SecVerWrite { .. } => MANIFEST_EXT_ID_SECVER_WRITE,
            ManifestExtEntrySpec::Isfb { .. } => MANIFEST_EXT_ID_ISFB,
            ManifestExtEntrySpec::IsfbErasePolicy { .. } => MANIFEST_EXT_ID_ISFB_ERASE,
            ManifestExtEntrySpec::ImageType { image_type: _ } => MANIFEST_EXT_ID_IMAGE_TYPE,
            ManifestExtEntrySpec::DelegationCert { .. } => MANIFEST_EXT_ID_DELEGATION_CERT,
            ManifestExtEntrySpec::DelegationCertSpx { .. } => MANIFEST_EXT_ID_DELEGATION_CERT_SPX,
            ManifestExtEntrySpec::Raw { identifier, .. } => **identifier,
        }
    }

    pub fn is_signed(&self) -> bool {
        match self {
            ManifestExtEntrySpec::SpxKey { .. }
            | ManifestExtEntrySpec::SecVerWrite { .. }
            | ManifestExtEntrySpec::Isfb { .. }
            | ManifestExtEntrySpec::IsfbErasePolicy { .. }
            | ManifestExtEntrySpec::ImageType { .. }
            | ManifestExtEntrySpec::DelegationCert { .. }
            | ManifestExtEntrySpec::DelegationCertSpx { .. } => true,
            ManifestExtEntrySpec::SpxSignature { .. } => false,
            ManifestExtEntrySpec::Raw { signed, .. } => *signed,
        }
    }
}

impl ManifestExtEntry {
    /// Creates a new manifest extension from a given SPHINCS+ `key`.
    pub fn new_spx_key_entry(key: &SpxPublicKey) -> Result<Self> {
        Ok(ManifestExtEntry::SpxKey(ManifestExtSpxKey {
            header: ManifestExtHeader {
                identifier: MANIFEST_EXT_ID_SPX_KEY,
                name: MANIFEST_EXT_NAME_SPX_KEY,
            },
            key: SigverifySpxKey {
                data: le_bytes_to_word_arr(key.as_bytes())?,
            },
        }))
    }

    /// Creates a new manifest extension from a given SPHINCS+ `signature`.
    pub fn new_spx_signature_entry(signature: &[u8]) -> Result<Self> {
        Ok(ManifestExtEntry::SpxSignature(Box::new(
            ManifestExtSpxSignature {
                header: ManifestExtHeader {
                    identifier: MANIFEST_EXT_ID_SPX_SIGNATURE,
                    name: MANIFEST_EXT_NAME_SPX_SIGNATURE,
                },
                signature: SigverifySpxSignature {
                    data: le_bytes_to_word_arr(signature)?,
                },
            },
        )))
    }

    pub fn new_image_type_entry(image_type: u32) -> Result<Self> {
        Ok(ManifestExtEntry::ImageType(ManifestExtImageType {
            header: ManifestExtHeader {
                identifier: MANIFEST_EXT_ID_IMAGE_TYPE,
                name: MANIFEST_EXT_NAME_IMAGE_TYPE,
            },
            image_type,
        }))
    }

    pub fn new_secver_write_entry(write: u32) -> Result<Self> {
        Ok(ManifestExtEntry::SecVerWrite(ManifestExtSecVerWrite {
            header: ManifestExtHeader {
                identifier: MANIFEST_EXT_ID_SECVER_WRITE,
                name: MANIFEST_EXT_NAME_SECVER_WRITE,
            },
            write,
        }))
    }

    pub fn new_isfb_erase_policy_entry(erase_allowed: u32) -> Result<Self> {
        Ok(ManifestExtEntry::IsfbErasePolicy(
            ManifestExtIsfbErasePolicy {
                header: ManifestExtHeader {
                    identifier: MANIFEST_EXT_ID_ISFB_ERASE,
                    name: MANIFEST_EXT_NAME_ISFB_ERASE,
                },
                erase_allowed,
            },
        ))
    }

    pub fn new_isfb_entry(strike_mask: u128, product_expr_spec: Vec<ProductExpr>) -> Result<Self> {
        let product_expr_count = product_expr_spec.len() as u32;
        let product_expr = product_expr_spec
            .into_iter()
            .map(|expr| ManifestExtIsfbProductExpr {
                mask: expr.mask.0,
                value: expr.value.0,
            })
            .collect();
        Ok(ManifestExtEntry::Isfb(ManifestExtIsfb {
            header: ManifestExtHeader {
                identifier: MANIFEST_EXT_ID_ISFB,
                name: MANIFEST_EXT_NAME_ISFB,
            },
            strike_mask,
            product_expr_count,
            product_expr,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_delegation_cert_entry(
        version: u32,
        owner_key_id: u32,
        delegate_key_alg: u32,
        delegate_public_key: &EcdsaRawPublicKey,
        min_security_version: u32,
        max_security_version: u32,
        allowed_slots: u32,
        expiration_epoch: u64,
        usage_constraint: u32,
        device_id: [u32; 8],
        manuf_state_creator: u32,
        manuf_state_owner: u32,
        life_cycle_state: u32,
        owner_signature: Option<&EcdsaRawSignature>,
    ) -> Result<Self> {
        let x = le_bytes_to_word_arr(&delegate_public_key.x)?;
        let y = le_bytes_to_word_arr(&delegate_public_key.y)?;

        let mut owner_sig = SigverifyEcdsaSignature::default();
        if let Some(sig) = owner_signature {
            owner_sig.r = le_bytes_to_word_arr(&sig.r)?;
            owner_sig.s = le_bytes_to_word_arr(&sig.s)?;
        }

        Ok(ManifestExtEntry::DelegationCert(Box::new(ManifestExtDelegationCert {
            header: ManifestExtHeader {
                identifier: MANIFEST_EXT_ID_DELEGATION_CERT,
                name: MANIFEST_EXT_NAME_DELEGATION_CERT,
            },
            version,
            owner_key_id,
            delegate_key_alg,
            delegate_public_key: SigverifyEcdsaPublicKey { x, y },
            padding: 0,
            constraints: DelegationConstraints {
                min_security_version,
                max_security_version,
                allowed_slots,
                padding: 0,
                expiration_epoch,
                usage_constraint,
                device_id: LifecycleDeviceId { device_id },
                manuf_state_creator,
                manuf_state_owner,
                life_cycle_state,
                reserved: [0; 22],
            },
            owner_signature: owner_sig,
        })))
    }

    pub fn new_delegation_cert_spx_entry(
        delegate_spx_key: &SpxPublicKey,
        signature: Option<&[u8]>,
    ) -> Result<Self> {
        let mut sig = SigverifySpxSignature::default();
        if let Some(s) = signature {
            sig.data = le_bytes_to_word_arr(s)?;
        }

        Ok(ManifestExtEntry::DelegationCertSpx(Box::new(ManifestExtDelegationCertSpx {
            header: ManifestExtHeader {
                identifier: MANIFEST_EXT_ID_DELEGATION_CERT_SPX,
                name: MANIFEST_EXT_NAME_DELEGATION_CERT_SPX,
            },
            delegate_spx_key: SigverifySpxKey {
                data: le_bytes_to_word_arr(delegate_spx_key.as_bytes())?,
            },
            signature: sig,
        })))
    }

    /// Creates a new manifest extension from a given `spec`.
    pub fn from_spec(spec: &ManifestExtEntrySpec) -> Result<Self> {
        Ok(match spec {
            ManifestExtEntrySpec::SpxKey { spx_key } => {
                ManifestExtEntry::new_spx_key_entry(&SpxPublicKey::read_pem_file(spx_key)?)?
            }
            ManifestExtEntrySpec::SpxSignature { spx_signature } => {
                ManifestExtEntry::new_spx_signature_entry(&std::fs::read(spx_signature)?)?
            }
            ManifestExtEntrySpec::ImageType { image_type } => {
                ManifestExtEntry::new_image_type_entry(*image_type)?
            }
            ManifestExtEntrySpec::SecVerWrite { secver_write } => {
                ManifestExtEntry::new_secver_write_entry(
                    (if *secver_write {
                        HardenedBool::True
                    } else {
                        HardenedBool::False
                    })
                    .into(),
                )?
            }
            ManifestExtEntrySpec::IsfbErasePolicy { erase_allowed } => {
                ManifestExtEntry::new_isfb_erase_policy_entry(
                    (if *erase_allowed {
                        HardenedBool::True
                    } else {
                        HardenedBool::False
                    })
                    .into(),
                )?
            }
            ManifestExtEntrySpec::Isfb {
                strike_mask,
                product_expr,
            } => ManifestExtEntry::new_isfb_entry(**strike_mask, product_expr.to_vec())?,
            ManifestExtEntrySpec::DelegationCert {
                version,
                owner_key_id,
                delegate_key_alg,
                delegate_public_key,
                min_security_version,
                max_security_version,
                allowed_slots,
                expiration_epoch,
                usage_constraint,
                device_id,
                manuf_state_creator,
                manuf_state_owner,
                life_cycle_state,
                owner_signature,
            } => {
                let delegate_pub = match delegate_public_key {
                    PathOrRaw::Path(path) => {
                        let key = EcdsaPublicKey::load(path)?;
                        EcdsaRawPublicKey::try_from(&key)?
                    }
                    PathOrRaw::Raw(raw) => raw.clone(),
                };
                let raw_owner_sig = match owner_signature {
                    Some(PathOrRaw::Path(path)) => Some(EcdsaRawSignature::read_from_file(path)?),
                    Some(PathOrRaw::Raw(raw)) => Some(raw.clone()),
                    None => None,
                };
                ManifestExtEntry::new_delegation_cert_entry(
                    *version,
                    *owner_key_id,
                    *delegate_key_alg,
                    &delegate_pub,
                    *min_security_version,
                    *max_security_version,
                    *allowed_slots,
                    *expiration_epoch,
                    *usage_constraint,
                    *device_id,
                    *manuf_state_creator,
                    *manuf_state_owner,
                    *life_cycle_state,
                    raw_owner_sig.as_ref(),
                )?
            }
            ManifestExtEntrySpec::DelegationCertSpx {
                delegate_spx_key,
                signature,
            } => {
                let delegate_spx = match delegate_spx_key {
                    PathOrRaw::Path(path) => SpxPublicKey::read_pem_file(path)?,
                    PathOrRaw::Raw(raw) => SpxPublicKey::from_bytes(SphincsPlus::Sha2128sSimple, raw.as_slice())?,
                };
                let sig_bytes = match signature {
                    Some(PathOrRaw::Path(path)) => Some(std::fs::read(path)?),
                    Some(PathOrRaw::Raw(raw)) => Some(raw.clone()),
                    None => None,
                };
                ManifestExtEntry::new_delegation_cert_spx_entry(
                    &delegate_spx,
                    sig_bytes.as_deref(),
                )?
            }
            ManifestExtEntrySpec::Raw {
                name,
                identifier,
                value,
                ..
            } => ManifestExtEntry::Raw {
                header: ManifestExtHeader {
                    identifier: **identifier,
                    name: **name,
                },
                data: value.iter().map(|v| **v).collect(),
            },
        })
    }

    /// Returns the header portion of this extension.
    pub fn header(&self) -> &ManifestExtHeader {
        match self {
            ManifestExtEntry::SpxKey(key) => &key.header,
            ManifestExtEntry::SpxSignature(sig) => &sig.header,
            ManifestExtEntry::ImageType(image_type) => &image_type.header,
            ManifestExtEntry::SecVerWrite(sv) => &sv.header,
            ManifestExtEntry::Isfb(isfb) => &isfb.header,
            ManifestExtEntry::IsfbErasePolicy(erase) => &erase.header,
            ManifestExtEntry::DelegationCert(cert) => &cert.header,
            ManifestExtEntry::DelegationCertSpx(cert) => &cert.header,
            ManifestExtEntry::Raw { header, data: _ } => header,
        }
    }

    /// Allocates a new byte `Vec<u8>` and writes the binary extension data to it.
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            ManifestExtEntry::SpxKey(key) => key.as_bytes().to_vec(),
            ManifestExtEntry::SpxSignature(sig) => sig.as_bytes().to_vec(),
            ManifestExtEntry::ImageType(image_type) => image_type.as_bytes().to_vec(),
            ManifestExtEntry::SecVerWrite(sv) => sv.as_bytes().to_vec(),
            ManifestExtEntry::Isfb(isfb) => isfb.to_vec().unwrap(),
            ManifestExtEntry::IsfbErasePolicy(erase) => erase.as_bytes().to_vec(),
            ManifestExtEntry::DelegationCert(cert) => cert.as_bytes().to_vec(),
            ManifestExtEntry::DelegationCertSpx(cert) => cert.as_bytes().to_vec(),
            ManifestExtEntry::Raw { header, data } => {
                header.as_bytes().iter().chain(data).copied().collect()
            }
        }
    }

    /// Parses a manifest extension entry from its identifier and raw byte representation.
    pub fn parse(identifier: u32, bytes: &[u8]) -> Result<Self> {
        match identifier {
            MANIFEST_EXT_ID_SPX_KEY => {
                let ext = ManifestExtSpxKey::read_from_bytes(bytes)
                    .map_err(|_| anyhow::anyhow!("Failed to parse SpxKey extension"))?;
                Ok(ManifestExtEntry::SpxKey(ext))
            }
            MANIFEST_EXT_ID_SPX_SIGNATURE => {
                let ext = ManifestExtSpxSignature::read_from_bytes(bytes)
                    .map_err(|_| anyhow::anyhow!("Failed to parse SpxSignature extension"))?;
                Ok(ManifestExtEntry::SpxSignature(Box::new(ext)))
            }
            MANIFEST_EXT_ID_IMAGE_TYPE => {
                let ext = ManifestExtImageType::read_from_bytes(bytes)
                    .map_err(|_| anyhow::anyhow!("Failed to parse ImageType extension"))?;
                Ok(ManifestExtEntry::ImageType(ext))
            }
            MANIFEST_EXT_ID_SECVER_WRITE => {
                let ext = ManifestExtSecVerWrite::read_from_bytes(bytes)
                    .map_err(|_| anyhow::anyhow!("Failed to parse SecVerWrite extension"))?;
                Ok(ManifestExtEntry::SecVerWrite(ext))
            }
            MANIFEST_EXT_ID_ISFB_ERASE => {
                let ext = ManifestExtIsfbErasePolicy::read_from_bytes(bytes)
                    .map_err(|_| anyhow::anyhow!("Failed to parse IsfbErasePolicy extension"))?;
                Ok(ManifestExtEntry::IsfbErasePolicy(ext))
            }
            MANIFEST_EXT_ID_DELEGATION_CERT => {
                let ext = ManifestExtDelegationCert::read_from_bytes(bytes)
                    .map_err(|_| anyhow::anyhow!("Failed to parse DelegationCert extension"))?;
                Ok(ManifestExtEntry::DelegationCert(Box::new(ext)))
            }
            MANIFEST_EXT_ID_DELEGATION_CERT_SPX => {
                let ext = ManifestExtDelegationCertSpx::read_from_bytes(bytes)
                    .map_err(|_| anyhow::anyhow!("Failed to parse DelegationCertSpx extension"))?;
                Ok(ManifestExtEntry::DelegationCertSpx(Box::new(ext)))
            }
            MANIFEST_EXT_ID_ISFB => {
                use byteorder::{LittleEndian, ReadBytesExt};
                let mut cursor = std::io::Cursor::new(bytes);
                let header = ManifestExtHeader::read_from_bytes(&bytes[0..8])
                    .map_err(|_| anyhow::anyhow!("Failed to parse Isfb header"))?;
                cursor.set_position(8);
                let strike_mask = cursor.read_u128::<LittleEndian>()?;
                let count = cursor.read_u32::<LittleEndian>()? as usize;
                let mut product_expr = Vec::new();
                for _ in 0..count {
                    let mask = cursor.read_u32::<LittleEndian>()?;
                    let value = cursor.read_u32::<LittleEndian>()?;
                    product_expr.push(ManifestExtIsfbProductExpr { mask, value });
                }
                Ok(ManifestExtEntry::Isfb(ManifestExtIsfb {
                    header,
                    strike_mask,
                    product_expr_count: count as u32,
                    product_expr,
                }))
            }
            _ => {
                // If it is a raw / unknown extension, parse it as raw
                if bytes.len() >= std::mem::size_of::<ManifestExtHeader>() {
                    let header = ManifestExtHeader::read_from_bytes(&bytes[0..std::mem::size_of::<ManifestExtHeader>()])
                        .map_err(|_| anyhow::anyhow!("Failed to parse Raw extension header"))?;
                    let data = bytes[std::mem::size_of::<ManifestExtHeader>()..].to_vec();
                    Ok(ManifestExtEntry::Raw { header, data })
                } else {
                    anyhow::bail!("Extension data is too small to contain header");
                }
            }
        }
    }
}impl TryFrom<&ManifestExtEntry> for ManifestExtEntrySpec {
    type Error = anyhow::Error;

    fn try_from(entry: &ManifestExtEntry) -> Result<Self> {
        match entry {
            ManifestExtEntry::SpxKey(_) => Ok(ManifestExtEntrySpec::SpxKey {
                spx_key: PathBuf::from("spx.pub.pem"),
            }),
            ManifestExtEntry::SpxSignature(_) => Ok(ManifestExtEntrySpec::SpxSignature {
                spx_signature: PathBuf::from("spx.sig"),
            }),
            ManifestExtEntry::ImageType(ext) => Ok(ManifestExtEntrySpec::ImageType {
                image_type: ext.image_type,
            }),
            ManifestExtEntry::SecVerWrite(ext) => Ok(ManifestExtEntrySpec::SecVerWrite {
                secver_write: ext.write != 0,
            }),
            ManifestExtEntry::IsfbErasePolicy(ext) => Ok(ManifestExtEntrySpec::IsfbErasePolicy {
                erase_allowed: ext.erase_allowed != 0,
            }),
            ManifestExtEntry::Isfb(isfb) => {
                let product_expr = isfb.product_expr
                    .iter()
                    .map(|pe| ProductExpr {
                        mask: HexEncoded(pe.mask),
                        value: HexEncoded(pe.value),
                    })
                    .collect::<Vec<_>>();
                Ok(ManifestExtEntrySpec::Isfb {
                    strike_mask: HexEncoded(isfb.strike_mask),
                    product_expr,
                })
            }
            ManifestExtEntry::DelegationCert(cert) => {
                let constraints = &cert.constraints;
                Ok(ManifestExtEntrySpec::DelegationCert {
                    version: cert.version,
                    owner_key_id: cert.owner_key_id,
                    delegate_key_alg: cert.delegate_key_alg,
                    delegate_public_key: PathOrRaw::Raw(EcdsaRawPublicKey {
                        x: cert.delegate_public_key.x.iter().flat_map(|w| w.to_le_bytes()).collect(),
                        y: cert.delegate_public_key.y.iter().flat_map(|w| w.to_le_bytes()).collect(),
                    }),
                    min_security_version: constraints.min_security_version,
                    max_security_version: constraints.max_security_version,
                    allowed_slots: constraints.allowed_slots,
                    expiration_epoch: constraints.expiration_epoch,
                    usage_constraint: constraints.usage_constraint,
                    device_id: constraints.device_id.device_id,
                    manuf_state_creator: constraints.manuf_state_creator,
                    manuf_state_owner: constraints.manuf_state_owner,
                    life_cycle_state: constraints.life_cycle_state,
                    owner_signature: Some(PathOrRaw::Raw(EcdsaRawSignature {
                        r: cert.owner_signature.r.iter().flat_map(|w| w.to_le_bytes()).collect(),
                        s: cert.owner_signature.s.iter().flat_map(|w| w.to_le_bytes()).collect(),
                    })),
                })
            }
            ManifestExtEntry::DelegationCertSpx(cert) => {
                Ok(ManifestExtEntrySpec::DelegationCertSpx {
                    delegate_spx_key: PathOrRaw::Raw(cert.delegate_spx_key.as_bytes().to_vec()),
                    signature: Some(PathOrRaw::Raw(cert.signature.as_bytes().to_vec())),
                })
            }
            ManifestExtEntry::Raw { header, data } => {
                Ok(ManifestExtEntrySpec::Raw {
                    name: HexEncoded(header.name),
                    identifier: HexEncoded(header.identifier),
                    value: data.iter().map(|&b| HexEncoded(b)).collect(),
                    signed: false,
                })
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hexdump::hexdump_string;
    use crate::util::num_de::HexEncoded;
    use crate::util::testdata;

    #[test]
    fn test_manifest_ext_from_hjson() {
        let spec = ManifestExtSpec::read_from_file(&testdata("image/manifest_ext.hjson")).unwrap();
        assert_eq!(spec.source_path(), Some(testdata("image").as_path()));
        assert_eq!(spec.extension_params.len(), 6);
        assert_eq!(
            spec.extension_params[0],
            ManifestExtEntrySpec::SpxKey {
                spx_key: "test_spx.pem".into()
            }
        );
        assert!(spec.extension_params[0].is_signed());
        assert_eq!(
            spec.extension_params[1],
            ManifestExtEntrySpec::SecVerWrite { secver_write: true }
        );
        assert!(spec.extension_params[1].is_signed());
        assert_eq!(
            spec.extension_params[2],
            ManifestExtEntrySpec::Isfb {
                strike_mask: HexEncoded(0x0fedcba987654321fedcba9876543210),
                product_expr: vec![
                    ProductExpr {
                        mask: HexEncoded(0xffffffff),
                        value: HexEncoded(0xa5a5a5a5),
                    },
                    ProductExpr {
                        mask: HexEncoded(0xf0f0f0f0),
                        value: HexEncoded(0xa0a0a0a0),
                    },
                ]
            }
        );
        assert!(spec.extension_params[2].is_signed());
        assert_eq!(
            spec.extension_params[3],
            ManifestExtEntrySpec::IsfbErasePolicy {
                erase_allowed: false
            }
        );
        assert!(spec.extension_params[3].is_signed());
        assert_eq!(
            spec.extension_params[4],
            ManifestExtEntrySpec::Raw {
                name: HexEncoded(0xbeef),
                identifier: HexEncoded(0xabcd),
                signed: true,
                value: [0x01, 0x23, 0x45, 0x67].map(HexEncoded).to_vec()
            }
        );
        assert!(spec.extension_params[4].is_signed());
        assert_eq!(
            spec.extension_params[5],
            ManifestExtEntrySpec::SpxSignature {
                spx_signature: "test_signature.bin".into()
            }
        );
        assert!(!spec.extension_params[5].is_signed());
    }

    const MAN_EXT_ISFB_CONF: &str = "\
00000000: 49 53 46 42 49 53 46 42 10 32 54 76 98 ba dc fe  ISFBISFB.2Tv....
00000010: 21 43 65 87 a9 cb ed 0f 02 00 00 00 4f 30 50 10  !Ce.........O0P.
00000020: 05 00 00 01 f0 f0 f0 f0 a0 a0 a0 a0              ............
";
    #[test]
    fn test_man_ext_isfb_write() -> Result<()> {
        let isfb = ManifestExtEntry::new_isfb_entry(
            0x0fedcba987654321fedcba9876543210,
            vec![
                ProductExpr {
                    mask: HexEncoded(0x1050304f),
                    value: HexEncoded(0x01000005),
                },
                ProductExpr {
                    mask: HexEncoded(0xf0f0f0f0),
                    value: HexEncoded(0xa0a0a0a0),
                },
            ],
        )?;

        let bin = isfb.to_vec();
        eprintln!("{}", hexdump_string(&bin)?);
        assert_eq!(hexdump_string(&bin)?, MAN_EXT_ISFB_CONF);
        Ok(())
    }

    const MAN_EXT_ISFB_ERASE_POLICY: &str = "\
00000000: 49 53 46 45 49 53 46 45 d4 01 00 00              ISFEISFE....
";

    #[test]
    fn test_man_ext_isfb_erase_policy_write() -> Result<()> {
        let isfb = ManifestExtEntry::new_isfb_erase_policy_entry(HardenedBool::False.into())?;

        let bin = isfb.to_vec();
        eprintln!("{}", hexdump_string(&bin)?);
        assert_eq!(hexdump_string(&bin)?, MAN_EXT_ISFB_ERASE_POLICY);
        Ok(())
    }

    #[test]
    fn test_delegation_cert_spec_parse() {
        let hjson = r#"{
            extension_params: [
                {
                    delegation_cert: {
                        version: 1,
                        owner_key_id: 2,
                        delegate_key_alg: 1,
                        delegate_public_key: "test_delegate.pub.der",
                        min_security_version: 1,
                        max_security_version: 10,
                        allowed_slots: 3,
                        expiration_epoch: 12345678,
                        usage_constraint: 16384,
                        device_id: [1, 2, 3, 4, 5, 6, 7, 8],
                        manuf_state_creator: 0,
                        manuf_state_owner: 0,
                        life_cycle_state: 4294967295,
                        owner_signature: "test_owner.sig"
                    }
                },
                {
                    delegation_cert_spx: {
                        delegate_spx_key: "test_spx.pem",
                        signature: "test_spx.sig"
                    }
                }
            ]
        }"#;

        let spec: ManifestExtSpec = deser_hjson::from_str(hjson).unwrap();
        assert_eq!(spec.extension_params.len(), 2);

        if let ManifestExtEntrySpec::DelegationCert {
            version,
            owner_key_id,
            delegate_public_key,
            device_id,
            owner_signature,
            ..
        } = &spec.extension_params[0] {
            assert_eq!(*version, 1);
            assert_eq!(*owner_key_id, 2);
            assert_eq!(delegate_public_key.to_str().unwrap(), "test_delegate.pub.der");
            assert_eq!(device_id, &[1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(owner_signature.as_ref().unwrap().to_str().unwrap(), "test_owner.sig");
        } else {
            panic!("Expected DelegationCert");
        }

        if let ManifestExtEntrySpec::DelegationCertSpx {
            delegate_spx_key,
            signature,
        } = &spec.extension_params[1] {
            assert_eq!(delegate_spx_key.to_str().unwrap(), "test_spx.pem");
            assert_eq!(signature.as_ref().unwrap().to_str().unwrap(), "test_spx.sig");
        } else {
            panic!("Expected DelegationCertSpx");
        }
    }

    #[test]
    fn test_delegation_cert_binary_generation() -> Result<()> {
        let raw_pub = EcdsaRawPublicKey {
            x: vec![0x11u8; 32],
            y: vec![0x22u8; 32],
        };
        let raw_sig = EcdsaRawSignature {
            r: vec![0x33u8; 32],
            s: vec![0x44u8; 32],
        };

        let entry = ManifestExtEntry::new_delegation_cert_entry(
            1, // version
            2, // owner_key_id
            1, // delegate_key_alg
            &raw_pub,
            1, // min_security_version
            10, // max_security_version
            3, // allowed_slots
            12345678, // expiration_epoch
            16384, // usage_constraint
            [0xAA; 8], // device_id
            0, // manuf_state_creator
            0, // manuf_state_owner
            0xFFFFFFFF, // life_cycle_state
            Some(&raw_sig),
        )?;

        let bytes = entry.to_vec();
        assert_eq!(bytes.len(), 312);

        // Verify some header fields
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), MANIFEST_EXT_ID_DELEGATION_CERT);
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), MANIFEST_EXT_NAME_DELEGATION_CERT);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 1); // version
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 2); // owner_key_id

        // Verify delegate key algorithm
        assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 1);

        // Verify delegate_public_key.x contains 0x11
        for b in &bytes[20..52] {
            assert_eq!(*b, 0x11);
        }

        // Verify delegate_public_key.y contains 0x22
        for b in &bytes[52..84] {
            assert_eq!(*b, 0x22);
        }

        // Verify owner_signature.r contains 0x33
        for b in &bytes[248..280] {
            assert_eq!(*b, 0x33);
        }

        // Verify owner_signature.s contains 0x44
        for b in &bytes[280..312] {
            assert_eq!(*b, 0x44);
        }

        Ok(())
    }
}
