use anyhow::{Context, Result};
use std::str::FromStr;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::TpmHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::structures::{
    HashScheme, Public, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
    RsaExponent, RsaScheme, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context as TpmContext;

const AK_HANDLE: u32 = 0x81010002;
const TPM_DEVICE: &str = "/dev/tpm0";

/// RSA 2048 Endorsement Key template used as transient parent for AK creation.
///
/// Restricted decrypt key under the Endorsement hierarchy with AES-128-CFB
/// symmetric protection. Uses user_with_auth (not admin_with_policy) so that
/// null auth sessions work for create/load — the EK is transient and flushed
/// immediately after AK provisioning.
fn ek_rsa_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_restricted(true)
        .with_decrypt(true)
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .build()?;

    let rsa_params = PublicRsaParametersBuilder::new()
        .with_scheme(RsaScheme::Null)
        .with_key_bits(tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_symmetric(SymmetricDefinitionObject::Aes {
            key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes128,
            mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
        })
        .with_restricted(true)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .build()?;

    // Zero-filled unique field for deterministic EK
    let unique = PublicKeyRsa::new_empty_with_size(
        tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048,
    );

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(unique)
        .build()
        .context("failed to build EK RSA template")
}

/// RSA 2048 Attestation Key template (matches `tpm2_createak -G rsa -g sha256 -s rsassa`).
///
/// Signing key with RSASSA-SHA256 scheme, created under the EK.
fn ak_rsa_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_restricted(true)
        .with_sign_encrypt(true)
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .build()?;

    let rsa_params = PublicRsaParametersBuilder::new()
        .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_key_bits(tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_restricted(true)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .context("failed to build AK RSA template")
}

/// Provision a TPM Attestation Key at persistent handle 0x81010002.
///
/// Idempotent: if the handle is already occupied, exits successfully.
/// Equivalent to:
///   tpm2_createek -c ek.ctx -G rsa
///   tpm2_createak -C ek.ctx -c ak.ctx -G rsa -g sha256 -s rsassa
///   tpm2_evictcontrol -c ak.ctx 0x81010002
fn provision_ak() -> Result<()> {
    let tcti = TctiNameConf::from_str(&format!("device:{TPM_DEVICE}"))
        .context("failed to create TCTI config")?;
    let mut ctx = TpmContext::new(tcti).context("failed to create TPM context")?;

    // Check if AK already persisted at the target handle
    let tpm_handle: TpmHandle = AK_HANDLE.try_into().context("invalid AK handle")?;
    let already_exists = ctx
        .execute_with_nullauth_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
        .is_ok();

    if already_exists {
        log::info!("AK already exists at handle {:#X}, nothing to do", AK_HANDLE);
        return Ok(());
    }

    log::info!("provisioning RSA AK at handle {:#X}", AK_HANDLE);

    let ek_template = ek_rsa_template()?;
    let ak_template = ak_rsa_template()?;

    ctx.execute_with_nullauth_session(|ctx| -> std::result::Result<(), tss_esapi::Error> {
        // Create transient EK
        let ek = ctx.create_primary(Hierarchy::Endorsement, ek_template, None, None, None, None)?;
        log::info!("created transient EK");

        // Create AK under EK
        let ak = ctx.create(ek.key_handle, ak_template, None, None, None, None)?;
        log::info!("created AK key pair");

        // Load AK into TPM
        let ak_handle = ctx.load(ek.key_handle, ak.out_private, ak.out_public)?;
        log::info!("loaded AK");

        // Persist AK at target handle
        let persistent = tss_esapi::handles::PersistentTpmHandle::new(AK_HANDLE)?;
        ctx.evict_control(
            tss_esapi::interface_types::resource_handles::Provision::Owner,
            ak_handle.into(),
            Persistent::Persistent(persistent),
        )?;
        log::info!("persisted AK at handle {:#X}", AK_HANDLE);

        // Flush transient EK (AK transient handle consumed by evict_control)
        ctx.flush_context(ek.key_handle.into())?;

        Ok(())
    })
    .context("TPM AK provisioning failed")?;

    log::info!("AK provisioning complete");
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    provision_ak()
}
