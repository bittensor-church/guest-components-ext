use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;

const DEFAULT_INIT_DATA_PATH: &str = "/run/confidential-containers/initdata/init_data.toml";
const INIT_DATA_PATH_ENV: &str = "CC_INIT_DATA";

#[derive(Deserialize)]
struct InitData {
    data: InitDataFields,
}

#[derive(Deserialize)]
struct InitDataFields {
    domain_separator: Option<String>,
}

pub struct ParsedInitData {
    pub domain_separator: String,
    pub init_data_digest: [u8; 32],
}

pub fn parse() -> Result<ParsedInitData> {
    let path = std::env::var(INIT_DATA_PATH_ENV)
        .unwrap_or_else(|_| DEFAULT_INIT_DATA_PATH.to_string());
    let path = Path::new(&path);

    let raw = std::fs::read(path)
        .with_context(|| format!("failed to read init_data from {}", path.display()))?;

    let init_data: InitData = toml::from_str(
        std::str::from_utf8(&raw).context("init_data.toml is not valid UTF-8")?,
    )
    .context("failed to parse init_data.toml")?;

    let domain_separator = match init_data.data.domain_separator {
        Some(ds) if !ds.is_empty() => ds,
        _ => bail!("data.domain_separator is missing or empty in init_data.toml (security gate)"),
    };

    let init_data_digest: [u8; 32] = Sha256::digest(&raw).into();

    Ok(ParsedInitData {
        domain_separator,
        init_data_digest,
    })
}
