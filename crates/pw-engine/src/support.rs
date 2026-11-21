// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Support bundle (M4): the zip a user attaches to a ticket. It is built locally, previewed before
//! saving, and never uploaded. The agent keeps the finished zip in its own protected folder and hands
//! it to the client in chunks, so a non-administrator operator can save it in their own folder.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use pw_proto::{
    CaptureStatus, ErrorCode, ErrorPayload, LiveStats, PayloadView, RecordModeView,
    RecordStartRequest, SupportBundleInfo, SupportBundleRequest, SupportChunk, SupportItem,
    SupportPreview, SupportReadRequest, SystemInfo,
};

use crate::capture::{ensure_private_dir, CaptureManager};

pub const MAX_CAPTURE_SECS: u32 = 120;
/// Bundles waiting to be read are deleted after this long.
const KEEP_BUNDLES: Duration = Duration::from_secs(60 * 60);
/// Most bytes of a text file shown in the preview.
const SAMPLE_BYTES: usize = 1800;
/// Most bytes kept from the end of each log file.
const LOG_TAIL_BYTES: u64 = 512 * 1024;
const LOG_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_CHUNK: u32 = 512 * 1024;

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::BadRequest, message)
}

fn internal(message: impl ToString) -> ErrorPayload {
    ErrorPayload::new(ErrorCode::Internal, message.to_string())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What the engine knows right now, gathered by the caller.
pub struct Inputs {
    pub info: SystemInfo,
    pub stats: Option<LiveStats>,
    pub capture: CaptureStatus,
}

/// One file before it is zipped.
pub struct BundleFile {
    pub name: String,
    pub description: String,
    pub data: Vec<u8>,
    pub text: bool,
}

impl BundleFile {
    fn text(name: &str, description: &str, body: String) -> Self {
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            data: body.into_bytes(),
            text: true,
        }
    }

    fn item(&self) -> SupportItem {
        SupportItem {
            name: self.name.clone(),
            description: self.description.clone(),
            bytes: self.data.len() as u64,
            sample: self.text.then(|| sample_of(&self.data)),
        }
    }
}

fn sample_of(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data);
    let mut end = text.len().min(SAMPLE_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut sample = text[..end].to_owned();
    if end < text.len() {
        sample.push_str("\n… (shortened in this preview)");
    }
    sample
}

pub struct SupportService {
    dir: PathBuf,
    logs_dir: PathBuf,
    bundles: Mutex<HashMap<String, (PathBuf, SystemTime)>>,
}

impl SupportService {
    pub fn new(dir: PathBuf, logs_dir: PathBuf) -> Self {
        Self {
            dir,
            logs_dir,
            bundles: Mutex::new(HashMap::new()),
        }
    }

    /// Everything except the packet capture, with the anonymization already applied.
    pub fn collect(
        &self,
        inputs: &Inputs,
        request: &SupportBundleRequest,
    ) -> (Vec<BundleFile>, u32) {
        let hostname = inputs.info.hostname.clone();
        let local = local_addresses(&inputs.capture);
        let mut files = vec![
            BundleFile::text(
                "summary.txt",
                "PacketWard and Windows versions, uptime and when this bundle was made",
                summary_text(inputs),
            ),
            BundleFile::text(
                "traffic.txt",
                "Current traffic, connection counts, busiest remote addresses and RDP sessions",
                traffic_text(inputs.stats.as_ref()),
            ),
            BundleFile::text(
                "adapters.txt",
                "Network adapters, their addresses and current throughput",
                adapters_text(inputs),
            ),
            BundleFile::text(
                "capture-backend.txt",
                "Which packet capture backend is used and what is missing",
                capture_text(&inputs.capture),
            ),
        ];
        if request.include_logs {
            files.extend(self.log_files());
        }
        files.extend(network_command_files());
        let mut hidden = 0;
        if request.anonymize_local_ips {
            let map = placeholder_map(&local);
            hidden = map.len() as u32;
            for file in files.iter_mut().filter(|f| f.text) {
                let text = String::from_utf8_lossy(&file.data).into_owned();
                file.data = anonymize(&text, &map, &hostname).into_bytes();
            }
        }
        (files, hidden)
    }

    pub fn preview(&self, inputs: &Inputs, request: &SupportBundleRequest) -> SupportPreview {
        let (files, hidden) = self.collect(inputs, request);
        let mut items: Vec<SupportItem> = files.iter().map(BundleFile::item).collect();
        if request.capture_secs > 0 && !request.anonymize_local_ips {
            items.push(SupportItem {
                name: "capture.pcapng".to_owned(),
                description: format!(
                    "{} seconds of traffic (first 128 bytes of each packet, no content). Recorded when you save; \
                     it contains this machine's real addresses.",
                    request.capture_secs.min(MAX_CAPTURE_SECS)
                ),
                bytes: 0,
                sample: None,
            });
        }
        SupportPreview {
            items,
            local_addrs_hidden: hidden,
        }
    }

    /// Builds the zip, records the traffic sample first when asked, and keeps it for reading.
    pub async fn create(
        &self,
        inputs: Inputs,
        request: SupportBundleRequest,
        capture: &CaptureManager,
    ) -> Result<SupportBundleInfo, ErrorPayload> {
        if request.capture_secs > MAX_CAPTURE_SECS {
            return Err(bad_request(format!(
                "the traffic sample is limited to {MAX_CAPTURE_SECS} seconds"
            )));
        }
        let (mut files, _) = self.collect(&inputs, &request);
        if request.capture_secs > 0 && !request.anonymize_local_ips {
            match record_sample(capture, request.capture_secs).await {
                Ok(Some(data)) => files.push(BundleFile {
                    name: "capture.pcapng".to_owned(),
                    description: "Short traffic sample (packet headers only)".to_owned(),
                    data,
                    text: false,
                }),
                Ok(None) => {}
                // The rest of the bundle is still useful; say what is missing.
                Err(err) => files.push(BundleFile::text(
                    "capture-error.txt",
                    "Why the traffic sample is missing",
                    format!(
                        "The traffic sample could not be recorded: {}\n",
                        err.message
                    ),
                )),
            }
        }
        let items: Vec<SupportItem> = files.iter().map(BundleFile::item).collect();
        ensure_private_dir(&self.dir).map_err(|e| internal(format!("support folder: {e}")))?;
        self.cleanup();
        let id = format!("{:016x}", rand_id());
        let path = self.dir.join(format!("{id}.zip"));
        let bytes = tokio::task::spawn_blocking({
            let path = path.clone();
            move || write_zip(&path, &files)
        })
        .await
        .map_err(internal)?
        .map_err(|e| internal(format!("could not write the bundle: {e}")))?;
        lock(&self.bundles).insert(id.clone(), (path, SystemTime::now()));
        Ok(SupportBundleInfo {
            id,
            name: format!("packetward-support-{}.zip", date_stamp(unix_secs())),
            bytes,
            items,
        })
    }

    pub fn read(&self, request: &SupportReadRequest) -> Result<SupportChunk, ErrorPayload> {
        use std::io::{Read, Seek, SeekFrom};
        let path = lock(&self.bundles)
            .get(&request.id)
            .map(|(p, _)| p.clone())
            .ok_or_else(|| bad_request("unknown or expired bundle"))?;
        let mut file = fs::File::open(&path).map_err(internal)?;
        let total = file.metadata().map_err(internal)?.len();
        let len = u64::from(request.len.clamp(1, MAX_CHUNK));
        file.seek(SeekFrom::Start(request.offset.min(total)))
            .map_err(internal)?;
        let mut buffer = Vec::new();
        file.take(len).read_to_end(&mut buffer).map_err(internal)?;
        let end = request.offset.min(total) + buffer.len() as u64;
        Ok(SupportChunk {
            data_b64: base64::engine::general_purpose::STANDARD.encode(&buffer),
            eof: end >= total,
        })
    }

    pub fn discard(&self, id: &str) {
        if let Some((path, _)) = lock(&self.bundles).remove(id) {
            let _ = fs::remove_file(path);
        }
    }

    /// Deletes bundles nobody collected within an hour, and orphans of a previous run.
    pub fn cleanup(&self) {
        let now = SystemTime::now();
        let mut bundles = lock(&self.bundles);
        bundles.retain(|_, (path, made)| {
            let keep = now
                .duration_since(*made)
                .is_ok_and(|age| age < KEEP_BUNDLES);
            if !keep {
                let _ = fs::remove_file(&*path);
            }
            keep
        });
        let known: Vec<PathBuf> = bundles.values().map(|(p, _)| p.clone()).collect();
        drop(bundles);
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let is_zip = path.extension().is_some_and(|e| e == "zip");
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age > KEEP_BUNDLES);
            if is_zip && old && !known.contains(&path) {
                let _ = fs::remove_file(path);
            }
        }
    }

    fn log_files(&self) -> Vec<BundleFile> {
        let Ok(entries) = fs::read_dir(&self.logs_dir) else {
            return Vec::new();
        };
        let now = SystemTime::now();
        let mut files = Vec::new();
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let recent = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age < LOG_WINDOW);
            if name.starts_with("agent.log") && recent {
                if let Some(tail) = read_tail(&entry.path(), LOG_TAIL_BYTES) {
                    files.push(BundleFile {
                        name: format!("logs/{name}"),
                        description: "Agent log of the last 24 hours (end of the file)".to_owned(),
                        data: tail,
                        text: true,
                    });
                }
            }
        }
        files.sort_by(|a, b| a.name.cmp(&b.name));
        files
    }
}

fn rand_id() -> u64 {
    // Not a secret: the id only names a file the caller is already allowed to ask for. Time plus the
    // process id is unique enough across restarts.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    nanos ^ (u64::from(std::process::id()) << 32)
}

fn read_tail(path: &Path, max: u64) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(max))).ok()?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).ok()?;
    Some(data)
}

/// Records a short headers-only capture through the capture manager and returns the file's bytes.
async fn record_sample(
    capture: &CaptureManager,
    secs: u32,
) -> Result<Option<Vec<u8>>, ErrorPayload> {
    capture
        .record_start(RecordStartRequest {
            name: "support".to_owned(),
            mode: RecordModeView::Timed,
            duration_secs: Some(secs),
            filter: None,
            payload: PayloadView::Headers,
            confirm_full_payload: false,
        })
        .await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(u64::from(secs) + 15);
    let result = loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let recording = capture.status().recording;
        match recording {
            Some(r) if !r.running => break r.result,
            Some(_) if tokio::time::Instant::now() < deadline => {}
            _ => {
                capture.record_stop().await?;
                break capture.status().recording.and_then(|r| r.result);
            }
        }
    };
    let Some(result) = result else {
        return Ok(None);
    };
    let dir = PathBuf::from(capture.files().dir);
    let mut data = Vec::new();
    for name in &result.files {
        // Only our own finished capture file; names come from the recorder, never from a client.
        if let Ok(bytes) = fs::read(dir.join(name)) {
            if data.is_empty() {
                data = bytes;
            }
            let _ = capture.delete_file(name);
        }
    }
    Ok((!data.is_empty()).then_some(data))
}

fn write_zip(path: &Path, files: &[BundleFile]) -> std::io::Result<u64> {
    let file = fs::File::create(path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for entry in files {
        zip.start_file(&entry.name, options)
            .map_err(std::io::Error::other)?;
        zip.write_all(&entry.data)?;
    }
    let file = zip.finish().map_err(std::io::Error::other)?;
    file.metadata().map(|m| m.len())
}

// ---- texts ----------------------------------------------------------------------------------------

fn summary_text(inputs: &Inputs) -> String {
    let info = &inputs.info;
    format!(
        "PacketWard support bundle\n\
         Generated: {}\n\
         Agent version: {}\n\
         Protocol: {}.{}\n\
         Host: {} ({})\n\
         Agent: pid {}, uptime {} s, {}\n",
        utc_string(unix_secs()),
        info.agent_version,
        info.protocol_major,
        info.protocol_minor,
        info.hostname,
        info.os_family,
        info.pid,
        info.uptime_secs,
        if info.service_mode {
            "service"
        } else {
            "console"
        },
    )
}

fn traffic_text(stats: Option<&LiveStats>) -> String {
    let Some(stats) = stats else {
        return "No traffic sample yet.\n".to_owned();
    };
    let mbps = |bps: f64| bps / 1_000_000.0;
    let c = &stats.connections;
    let mut out = format!(
        "Traffic: in {:.2} Mbps ({:.0} pps), out {:.2} Mbps ({:.0} pps)\n\
         Connections: {} total, {} established, {} listening, {} time-wait, {} syn-received, {} other tcp, {} udp\n\
         RDP port: {}\n",
        mbps(stats.totals.in_bps),
        stats.totals.in_pps,
        mbps(stats.totals.out_bps),
        stats.totals.out_pps,
        c.total,
        c.established,
        c.listen,
        c.time_wait,
        c.syn_received,
        c.other_tcp,
        c.udp,
        stats.rdp_port,
    );
    out.push_str("\nBusiest remote addresses (by connections):\n");
    for talker in &stats.top_remote {
        out.push_str(&format!("  {:<40} {}\n", talker.addr, talker.connections));
    }
    out.push_str("\nRDP peers with an open connection:\n");
    for peer in &stats.rdp_peers {
        out.push_str(&format!("  {peer}\n"));
    }
    out.push_str("\nRDP sessions:\n");
    for session in &stats.rdp_sessions {
        out.push_str(&format!(
            "  session {} user {} state {:?} client {}\n",
            session.session_id, session.user, session.state, session.client_name
        ));
    }
    out.push_str(&format!(
        "\nAddresses with a successful RDP logon in the last {} days: {}\n",
        stats.rdp_trust.window_days,
        stats.rdp_trust.addresses.len()
    ));
    out
}

fn adapters_text(inputs: &Inputs) -> String {
    let mut out = String::from("Adapters known to the capture layer:\n");
    for adapter in &inputs.capture.interfaces {
        out.push_str(&format!(
            "  {} ({}) up={} addresses: {}\n",
            adapter.name,
            adapter.description,
            adapter.up,
            adapter.addrs.join(", ")
        ));
    }
    if let Some(stats) = &inputs.stats {
        out.push_str("\nThroughput per adapter:\n");
        for adapter in &stats.interfaces {
            out.push_str(&format!(
                "  {} kind={:?} up={} counted={} speed={} Mbps in={:.2} Mbps out={:.2} Mbps\n",
                adapter.name,
                adapter.kind,
                adapter.up,
                adapter.counts_toward_total,
                adapter.link_speed_bps / 1_000_000,
                adapter.in_bps / 1_000_000.0,
                adapter.out_bps / 1_000_000.0,
            ));
        }
    }
    out
}

fn capture_text(status: &CaptureStatus) -> String {
    let mut out = format!(
        "{}\nState: {:?}\nAdapter: {}\nBlind (outbound only): {}\nPackets: {} seen, {} delivered, {} dropped\n",
        status.selection.summary,
        status.state,
        status.interface.as_deref().unwrap_or("-"),
        status.blind,
        status.counters.received,
        status.counters.delivered,
        status.counters.dropped,
    );
    if let Some(error) = &status.error {
        out.push_str(&format!("Error: {error}\n"));
    }
    for missing in &status.selection.missing {
        out.push_str(&format!("Missing: {}\n", missing.message));
    }
    out
}

/// `ipconfig /all` and `route print`: read-only diagnostics support always asks for. (The one place
/// the project allows running system commands; core features never do.)
#[cfg(windows)]
fn network_command_files() -> Vec<BundleFile> {
    let run = |program: &str, args: &[&str]| -> String {
        match std::process::Command::new(program).args(args).output() {
            Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
            Err(err) => format!("could not run {program}: {err}\n"),
        }
    };
    let mut text = String::new();
    text.push_str("> ipconfig /all\n");
    text.push_str(&run("ipconfig", &["/all"]));
    text.push_str("\n> route print\n");
    text.push_str(&run("route", &["print"]));
    vec![BundleFile::text(
        "network-commands.txt",
        "Output of ipconfig /all and route print (read-only)",
        text,
    )]
}

#[cfg(not(windows))]
fn network_command_files() -> Vec<BundleFile> {
    Vec::new()
}

// ---- anonymization --------------------------------------------------------------------------------

fn local_addresses(capture: &CaptureStatus) -> Vec<IpAddr> {
    let mut addrs: Vec<IpAddr> = capture
        .interfaces
        .iter()
        .flat_map(|i| i.addrs.iter())
        .filter_map(|a| a.parse::<IpAddr>().ok())
        .map(|a| a.to_canonical())
        .filter(|a| !a.is_loopback() && !a.is_unspecified())
        .collect();
    addrs.sort();
    addrs.dedup();
    addrs
}

/// `(address as text, placeholder)`, longest text first so a longer address is never cut short.
fn placeholder_map(addrs: &[IpAddr]) -> Vec<(String, String)> {
    let (mut v4, mut v6) = (0, 0);
    let mut map: Vec<(String, String)> = addrs
        .iter()
        .map(|addr| {
            let label = if addr.is_ipv4() {
                v4 += 1;
                format!("LOCAL-IPV4-{v4}")
            } else {
                v6 += 1;
                format!("LOCAL-IPV6-{v6}")
            };
            (addr.to_string(), label)
        })
        .collect();
    map.sort_by_key(|(text, _)| std::cmp::Reverse(text.len()));
    map
}

fn is_addr_char(c: char) -> bool {
    c.is_ascii_hexdigit() || c == '.' || c == ':'
}

/// Replaces this machine's addresses (whole tokens only) and its name with placeholders.
pub fn anonymize(text: &str, map: &[(String, String)], hostname: &str) -> String {
    let mut out = text.to_owned();
    for (addr, label) in map {
        out = replace_token(&out, addr, label, is_addr_char);
    }
    if hostname.len() >= 3 && hostname != "unknown" {
        out = replace_token_ci(&out, hostname, "HOSTNAME");
    }
    out
}

/// Replaces `needle` where the characters around it are not part of the same address. A trailing
/// `.` or `:` followed by something that is not address-like (end of a sentence, a port) is allowed.
fn replace_token(text: &str, needle: &str, with: &str, is_part: impl Fn(char) -> bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut consumed = 0;
    while let Some(pos) = rest.find(needle) {
        let start = consumed + pos;
        let end = start + needle.len();
        let before = text[..start].chars().next_back();
        let after_str = &text[end..];
        let after = after_str.chars().next();
        let after_second = after_str.chars().nth(1);
        let boundary_before =
            before.is_none_or(|c| !is_part(c) || (c == ':' && !needle.contains(':')));
        let boundary_after = match after {
            None => true,
            Some(c) if !is_part(c) => true,
            // "10.0.0.5." or "10.0.0.5:443": the punctuation ends the address.
            Some('.') => !after_second.is_some_and(|n| n.is_ascii_digit()),
            Some(':') => !needle.contains(':'),
            Some(_) => false,
        };
        out.push_str(&rest[..pos]);
        if boundary_before && boundary_after {
            out.push_str(with);
        } else {
            out.push_str(needle);
        }
        rest = &rest[pos + needle.len()..];
        consumed = end;
    }
    out.push_str(rest);
    out
}

fn replace_token_ci(text: &str, needle: &str, with: &str) -> String {
    let lower = text.to_lowercase();
    let needle_lower = needle.to_lowercase();
    // `to_lowercase` can change lengths for exotic characters; fall back to no change then.
    if lower.len() != text.len() {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(pos) = lower[at..].find(&needle_lower) {
        let start = at + pos;
        let end = start + needle_lower.len();
        let word = |c: char| c.is_alphanumeric() || c == '_' || c == '-';
        let before_ok = text[..start].chars().next_back().is_none_or(|c| !word(c));
        let after_ok = text[end..].chars().next().is_none_or(|c| !word(c));
        out.push_str(&text[at..start]);
        out.push_str(if before_ok && after_ok {
            with
        } else {
            &text[start..end]
        });
        at = end;
    }
    out.push_str(&text[at..]);
    out
}

// ---- dates ----------------------------------------------------------------------------------------

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn date_stamp(secs: u64) -> String {
    let (y, m, d) = civil((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}",
        rem / 3600,
        (rem % 3600) / 60
    )
}

fn utc_string(secs: u64) -> String {
    let (y, m, d) = civil((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(addrs: &[&str]) -> Vec<(String, String)> {
        placeholder_map(&addrs.iter().map(|a| a.parse().unwrap()).collect::<Vec<_>>())
    }

    #[test]
    fn only_whole_addresses_are_replaced() {
        let m = map(&["10.0.0.5", "10.0.0.55"]);
        let text = "a 10.0.0.5 b 10.0.0.55 c 110.0.0.5 d 10.0.0.5:443 e 10.0.0.5. f 10.0.0.5.7";
        let out = anonymize(text, &m, "unknown");
        assert!(
            out.contains("a LOCAL-IPV4-1 b LOCAL-IPV4-2 c 110.0.0.5"),
            "{out}"
        );
        assert!(
            out.contains("d LOCAL-IPV4-1:443 e LOCAL-IPV4-1. f 10.0.0.5.7"),
            "{out}"
        );
    }

    #[test]
    fn remote_addresses_and_loopback_stay() {
        let capture_addrs = ["203.0.113.9"];
        let m = map(&capture_addrs);
        let out = anonymize(
            "peer 198.51.100.7 local 203.0.113.9 lo 127.0.0.1",
            &m,
            "unknown",
        );
        assert_eq!(out, "peer 198.51.100.7 local LOCAL-IPV4-1 lo 127.0.0.1");
    }

    #[test]
    fn ipv6_and_the_host_name() {
        let m = map(&["2001:db8::5"]);
        let out = anonymize(
            "v6 2001:db8::5 and [2001:db8::5]:3389 other 2001:db8::50 srv Web01-prod WEB01 web01",
            &m,
            "web01",
        );
        assert!(
            out.contains("v6 LOCAL-IPV6-1 and [LOCAL-IPV6-1]:3389"),
            "{out}"
        );
        assert!(out.contains("other 2001:db8::50"), "{out}");
        assert!(
            out.contains("Web01-prod"),
            "a longer word is not the host name: {out}"
        );
        assert!(out.contains("HOSTNAME HOSTNAME"), "{out}");
    }

    #[test]
    fn local_addresses_skip_loopback_and_duplicates() {
        let status = crate::capture::tests_support::status_with(&[
            "127.0.0.1",
            "10.0.0.5",
            "10.0.0.5",
            "::ffff:10.0.0.6",
        ]);
        let addrs = local_addresses(&status);
        assert_eq!(
            addrs,
            [
                "10.0.0.5".parse::<IpAddr>().unwrap(),
                "10.0.0.6".parse().unwrap()
            ]
        );
    }

    #[test]
    fn dates_are_right() {
        assert_eq!(utc_string(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc_string(1_763_545_825), "2025-11-19 09:50:25 UTC");
        assert_eq!(date_stamp(1_709_164_800), "20240229-0000"); // a leap day
    }

    #[test]
    fn the_preview_matches_what_is_zipped_and_anonymization_drops_the_capture() {
        let service = SupportService::new(PathBuf::from("unused"), PathBuf::from("no-logs"));
        let inputs = Inputs {
            info: SystemInfo {
                agent_version: "1".into(),
                protocol_major: 1,
                protocol_minor: 4,
                hostname: "SRV-WEB".into(),
                os_family: "windows".into(),
                pid: 1,
                uptime_secs: 5,
                service_mode: true,
            },
            stats: None,
            capture: crate::capture::tests_support::status_with(&["10.0.0.5"]),
        };
        let request = SupportBundleRequest {
            anonymize_local_ips: false,
            capture_secs: 30,
            include_logs: false,
        };
        let preview = service.preview(&inputs, &request);
        let names: Vec<&str> = preview.items.iter().map(|i| i.name.as_str()).collect();
        assert!(
            names.contains(&"summary.txt") && names.contains(&"capture.pcapng"),
            "{names:?}"
        );
        let adapters = preview
            .items
            .iter()
            .find(|i| i.name == "adapters.txt")
            .unwrap();
        assert!(adapters.sample.as_deref().unwrap().contains("10.0.0.5"));
        assert_eq!(preview.local_addrs_hidden, 0);

        let anonymous = service.preview(
            &inputs,
            &SupportBundleRequest {
                anonymize_local_ips: true,
                ..request
            },
        );
        assert!(anonymous.items.iter().all(|i| i.name != "capture.pcapng"));
        assert_eq!(anonymous.local_addrs_hidden, 1);
        let adapters = anonymous
            .items
            .iter()
            .find(|i| i.name == "adapters.txt")
            .unwrap();
        let sample = adapters.sample.as_deref().unwrap();
        assert!(
            sample.contains("LOCAL-IPV4-1") && !sample.contains("10.0.0.5"),
            "{sample}"
        );
        let summary = anonymous
            .items
            .iter()
            .find(|i| i.name == "summary.txt")
            .unwrap();
        assert!(summary.sample.as_deref().unwrap().contains("HOSTNAME"));
    }

    #[tokio::test]
    async fn a_bundle_is_a_valid_zip_that_can_be_read_in_chunks_and_discarded() {
        use crate::capture::tests_support::quiet_manager;
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        fs::create_dir(&logs).unwrap();
        fs::write(
            logs.join("agent.log.2026-11-19"),
            "line one\nline two with 10.0.0.5\n",
        )
        .unwrap();
        fs::write(logs.join("other.txt"), "not a log of ours").unwrap();
        let service = SupportService::new(dir.path().join("support"), logs);
        let (manager, _keep) = quiet_manager();
        let inputs = Inputs {
            info: SystemInfo {
                agent_version: "1".into(),
                protocol_major: 1,
                protocol_minor: 4,
                hostname: "SRV".into(),
                os_family: "windows".into(),
                pid: 1,
                uptime_secs: 5,
                service_mode: true,
            },
            stats: None,
            capture: manager.status(),
        };
        let info = service
            .create(
                inputs,
                SupportBundleRequest {
                    anonymize_local_ips: false,
                    capture_secs: 0,
                    include_logs: true,
                },
                &manager,
            )
            .await
            .unwrap();
        assert!(info.name.starts_with("packetward-support-") && info.name.ends_with(".zip"));
        assert!(info
            .items
            .iter()
            .any(|i| i.name == "logs/agent.log.2026-11-19"));
        assert!(info.items.iter().all(|i| i.name != "logs/other.txt"));

        // Read it back in small chunks, as a client would.
        let mut zip_bytes = Vec::new();
        loop {
            let chunk = service
                .read(&SupportReadRequest {
                    id: info.id.clone(),
                    offset: zip_bytes.len() as u64,
                    len: 300,
                })
                .unwrap();
            let data = base64::engine::general_purpose::STANDARD
                .decode(chunk.data_b64)
                .unwrap();
            zip_bytes.extend(data);
            if chunk.eof {
                break;
            }
        }
        assert_eq!(zip_bytes.len() as u64, info.bytes);
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).unwrap();
        let mut summary = String::new();
        archive
            .by_name("summary.txt")
            .unwrap()
            .read_to_string(&mut summary)
            .unwrap();
        assert!(summary.contains("Agent version: 1"));

        service.discard(&info.id);
        assert!(service
            .read(&SupportReadRequest {
                id: info.id,
                offset: 0,
                len: 10
            })
            .is_err());
    }

    #[tokio::test]
    async fn an_overlong_traffic_sample_is_refused() {
        use crate::capture::tests_support::quiet_manager;
        let dir = tempfile::tempdir().unwrap();
        let service = SupportService::new(dir.path().join("s"), dir.path().join("l"));
        let (manager, _keep) = quiet_manager();
        let inputs = Inputs {
            info: SystemInfo {
                agent_version: "1".into(),
                protocol_major: 1,
                protocol_minor: 4,
                hostname: "SRV".into(),
                os_family: "windows".into(),
                pid: 1,
                uptime_secs: 5,
                service_mode: true,
            },
            stats: None,
            capture: manager.status(),
        };
        let err = service
            .create(
                inputs,
                SupportBundleRequest {
                    anonymize_local_ips: false,
                    capture_secs: 999,
                    include_logs: false,
                },
                &manager,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
    }
}
