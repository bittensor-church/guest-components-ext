use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use std::fs;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

const CDH_RESOURCES_PATH: &str = "/etc/aa-offline_fs_kbc-resources.json";

fn create_fifo(path: &Path, mode: Mode) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("failed to remove stale FIFO {}", path.display()))?;
    }
    mkfifo(path, mode)
        .with_context(|| format!("failed to create FIFO at {}", path.display()))
}

/// Create a FIFO at the offline_fs_kbc resources path and serve the Ed25519
/// seed as JSON with base64-encoded value. Loops forever so CDH can reconnect
/// on restart.
pub fn serve(seed: &Zeroizing<[u8; 32]>) -> Result<()> {
    let encoded = B64.encode(seed.as_ref());
    let json = format!("{{\"default/key/1\": \"{encoded}\"}}\n");

    let path = Path::new(CDH_RESOURCES_PATH);
    let mode = Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IROTH;
    log::info!("serving CDH resources on FIFO {}", path.display());

    loop {
        create_fifo(path, mode)?;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("failed to open FIFO {} for writing", path.display()))?;

        file.write_all(json.as_bytes())
            .context("failed to write CDH resources to FIFO")?;
        drop(file);

        log::info!("served CDH resources to reader");
        fs::remove_file(path).ok();
    }
}
