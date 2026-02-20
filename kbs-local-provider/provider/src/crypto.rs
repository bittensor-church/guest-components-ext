use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Derive a 32-byte Ed25519 seed from AK public key and init_data.
///
/// - `ikm`: DER-encoded AK SubjectPublicKeyInfo — same bytes as `ak_public` in TEE evidence
/// - `salt`: SHA-256 digest of init_data.toml — binds key to launch configuration
/// - `info`: domain_separator string bytes — application-specific context
pub fn derive_ed25519_seed(
    ikm: &[u8],
    init_data_digest: &[u8; 32],
    domain_separator: &str,
) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(init_data_digest.as_ref()), ikm);
    let mut seed = Zeroizing::new([0u8; 32]);
    hk.expand(domain_separator.as_bytes(), seed.as_mut())
        .expect("32 bytes is valid for HKDF-SHA256");
    seed
}
