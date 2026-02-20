pub mod crypto;

#[cfg(feature = "tpm-provider")]
pub mod tpm;

use anyhow::Result;
use zeroize::Zeroizing;

/// Trait for TEE-specific seed providers.
///
/// Each provider returns input keying material (IKM) that is fed into
/// HKDF-SHA256 together with the init_data digest and domain separator
/// to derive a deterministic Ed25519 seed.
pub trait SeedProvider {
    /// Return the input keying material for HKDF seed derivation.
    fn ikm(&self) -> Result<Zeroizing<Vec<u8>>>;
}

/// Detect the available seed provider and return it.
///
/// Detection order: TPM → (TDX in the future) → error.
pub fn detect_provider() -> Result<Box<dyn SeedProvider>> {
    #[cfg(feature = "tpm-provider")]
    if tpm::detect_platform() {
        log::info!("detected TPM seed provider");
        return Ok(Box::new(tpm::TpmSeedProvider::default()));
    }

    anyhow::bail!("no seed provider detected")
}
