// SPDX-License-Identifier: GPL-3.0-or-later
//! `pwctl support-bundle`: builds the support zip through the agent and saves it on this machine.
//! Nothing is uploaded; the person attaches the file to their ticket.

use std::path::PathBuf;
use std::process::ExitCode;

use base64::Engine as _;
use pw_ipc::Client;
use pw_proto::{
    method, SupportBundleInfo, SupportBundleRequest, SupportChunk, SupportDiscardRequest,
    SupportPreview, SupportReadRequest,
};

use crate::status::connect_client;

const CHUNK: u32 = 256 * 1024;

pub struct Options {
    pub anonymize: bool,
    pub capture_secs: u32,
    pub no_logs: bool,
    pub out: Option<PathBuf>,
    pub preview_only: bool,
}

/// `Documents\PacketWard\support` of the current user.
fn default_dir() -> PathBuf {
    let home = std::env::var_os("USERPROFILE").map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join("Documents").join("PacketWard").join("support")
}

pub async fn run(options: Options) -> ExitCode {
    let client = match connect_client().await {
        Ok(client) => client,
        Err(code) => return code,
    };
    let request = SupportBundleRequest {
        anonymize_local_ips: options.anonymize,
        capture_secs: options.capture_secs,
        include_logs: !options.no_logs,
    };
    let preview: SupportPreview = match client.request(method::SUPPORT_PREVIEW, &request).await {
        Ok(preview) => preview,
        Err(err) => {
            eprintln!("The agent could not prepare the bundle: {err}");
            return ExitCode::from(1);
        }
    };
    println!("The bundle will contain:");
    for item in &preview.items {
        println!("  {:<28} {}", item.name, item.description);
    }
    if options.anonymize {
        println!(
            "This machine's own addresses ({} found) and its name are replaced with placeholders; the traffic sample is left out.",
            preview.local_addrs_hidden
        );
    } else if options.capture_secs > 0 {
        println!("Note: the traffic sample contains this machine's real addresses.");
    }
    if options.preview_only {
        return ExitCode::SUCCESS;
    }
    if options.capture_secs > 0 && !options.anonymize {
        println!("Recording {} seconds of traffic...", options.capture_secs);
    }
    let info: SupportBundleInfo = match client.request(method::SUPPORT_CREATE, &request).await {
        Ok(info) => info,
        Err(err) => {
            eprintln!("The bundle could not be created: {err}");
            return ExitCode::from(1);
        }
    };
    let result = save(&client, &info, options.out.unwrap_or_else(default_dir)).await;
    // The agent keeps its copy for an hour; remove it as soon as it is saved (or failed).
    let _ = client
        .request::<_, serde_json::Value>(
            method::SUPPORT_DISCARD,
            &SupportDiscardRequest {
                id: info.id.clone(),
            },
        )
        .await;
    match result {
        Ok(path) => {
            println!("Saved {} ({} bytes)", path.display(), info.bytes);
            println!("Attach this file to your support ticket. PacketWard never uploads it.");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("Could not save the bundle: {message}");
            ExitCode::from(1)
        }
    }
}

async fn save(client: &Client, info: &SupportBundleInfo, dir: PathBuf) -> Result<PathBuf, String> {
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(&info.name);
    let mut data = Vec::with_capacity(usize::try_from(info.bytes).unwrap_or(0));
    loop {
        let chunk: SupportChunk = client
            .request(
                method::SUPPORT_READ,
                &SupportReadRequest {
                    id: info.id.clone(),
                    offset: data.len() as u64,
                    len: CHUNK,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(chunk.data_b64)
            .map_err(|e| e.to_string())?;
        data.extend_from_slice(&bytes);
        if chunk.eof || bytes.is_empty() {
            break;
        }
    }
    if data.len() as u64 != info.bytes {
        return Err(format!("received {} of {} bytes", data.len(), info.bytes));
    }
    std::fs::write(&path, data).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}
