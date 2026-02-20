mod fifo;
mod initdata;

use anyhow::Result;

fn main() -> Result<()> {
    env_logger::init();

    let parsed = initdata::parse()?;
    log::info!("domain_separator: {}", parsed.domain_separator);

    let provider = provider::detect_provider()?;
    let ikm = provider.ikm()?;
    let seed = provider::crypto::derive_ed25519_seed(
        &ikm, &parsed.init_data_digest, &parsed.domain_separator,
    );

    fifo::serve(&seed)?;

    Ok(())
}
