use anyhow::{bail, Context, Result};
use std::str::FromStr;
use tss_esapi::abstraction::public::DecodedKey;
use tss_esapi::handles::TpmHandle;
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context as TpmContext;
use zeroize::Zeroizing;

use crate::SeedProvider;

const AK_HANDLE: u32 = 0x81010002;
const DEFAULT_TPM_DEVICE: &str = "/dev/tpm0";

/// Check if a TPM device is available.
pub fn detect_platform() -> bool {
    std::path::Path::new(DEFAULT_TPM_DEVICE).exists()
}

/// TPM-based seed provider.
///
/// Reads the AK public key from the persistent handle and returns its
/// DER-encoded SubjectPublicKeyInfo as input keying material. This is
/// the same byte representation that the CoCo attestation-agent puts
/// in the `ak_public` field of TPM evidence.
pub struct TpmSeedProvider {
    device: String,
}

impl Default for TpmSeedProvider {
    fn default() -> Self {
        Self {
            device: DEFAULT_TPM_DEVICE.to_string(),
        }
    }
}

impl SeedProvider for TpmSeedProvider {
    fn ikm(&self) -> Result<Zeroizing<Vec<u8>>> {
        ak_public_key_der(&self.device)
    }
}

/// Read the AK public key from TPM handle 0x81010002 and return it as
/// DER-encoded SubjectPublicKeyInfo bytes.
fn ak_public_key_der(tpm_device: &str) -> Result<Zeroizing<Vec<u8>>> {
    let tcti = TctiNameConf::from_str(&format!("device:{tpm_device}"))
        .context("failed to create TCTI config")?;
    let mut ctx = TpmContext::new(tcti).context("failed to create TPM context")?;

    let tpm_handle: TpmHandle = AK_HANDLE
        .try_into()
        .context("invalid AK handle")?;

    let ak_obj = ctx
        .execute_with_nullauth_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
        .context("AK not found at handle — was attestation-agent-init run?")?;

    let (ak_public, _, _) = ctx
        .read_public(ak_obj.into())
        .context("failed to read AK public key")?;

    let decoded: DecodedKey = ak_public
        .try_into()
        .context("failed to decode AK public key")?;

    let DecodedKey::RsaPublicKey(rsa_pk) = decoded else {
        bail!("AK is not an RSA key");
    };

    let spki = picky_asn1_x509::SubjectPublicKeyInfo::new_rsa_key(
        rsa_pk.modulus,
        rsa_pk.public_exponent,
    );
    let der = picky_asn1_der::to_vec(&spki)
        .context("failed to DER-encode AK public key")?;

    log::info!("read AK public key from handle {:#X} ({} bytes DER)", AK_HANDLE, der.len());
    Ok(Zeroizing::new(der))
}
