// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! Public speed-test providers built into the client, so the speed test works without any XeroHost node and
//! the user is not tied to one provider. All of them are free, need no account and no key, and are reached
//! over `https` only.
//!
//! | Group | Protocol | Download | Upload | Largest bin test |
//! |---|---|---|---|---|
//! | `cloudflare` | `GET /__down?bytes=N` (N < 100 MB), `POST /__up`, `/cdn-cgi/trace` | yes | yes | none (the service is not meant for gigabytes) |
//! | `hetzner` | static files `100MB.bin`, `1GB.bin`, `10GB.bin` read with `Range` | yes | no | 10 GiB |
//! | `ovh` | static files `100Mb.dat`, `1Gb.dat` read with `Range` | yes | no | 1 GiB |
//!
//! Observed limits (2026-11-20, from the dev VPS): Hetzner answers 429 to a third simultaneous connection and
//! to more than a few requests in quick succession; OVHcloud answers 429 to almost any second request within a
//! couple of seconds. So a mirror gets at most `max_streams` connections, its requests are spaced at least a
//! second apart (see `HttpTransport`), and a 429 on a transfer is retried with a pause instead of ending the run.
//!
//! The list is code, not downloaded data: nothing is fetched to learn it, and a hostname can only come from
//! here (or from the XeroHost node list / the user's own custom servers). Endpoints were checked on
//! 2026-11-20; a dead one simply loses the latency pick and is reported as dead.

use super::server::{Scheme, ServerEndpoint, ServerKind};

/// A static file of a mirror, read with a `Range` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorFile {
    /// Absolute path on the host.
    pub path: &'static str,
    /// Exact size in bytes.
    pub bytes: u64,
}

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

const HETZNER_FILES: &[MirrorFile] = &[
    MirrorFile {
        path: "/100MB.bin",
        bytes: 100 * MIB,
    },
    MirrorFile {
        path: "/1GB.bin",
        bytes: GIB,
    },
    MirrorFile {
        path: "/10GB.bin",
        bytes: 10 * GIB,
    },
];

const OVH_FILES: &[MirrorFile] = &[
    MirrorFile {
        path: "/files/100Mb.dat",
        bytes: 100 * MIB,
    },
    MirrorFile {
        path: "/files/1Gb.dat",
        bytes: GIB,
    },
];

/// Largest request Cloudflare answers (it refuses 100 000 000 and above); kept well below.
pub const CLOUDFLARE_MAX_DOWNLOAD: u64 = 90_000_000;
/// Upload body per request to Cloudflare (it accepted 100 MB; one tenth of that is plenty and polite).
pub const CLOUDFLARE_MAX_UPLOAD: u64 = 25 * MIB;

/// One built-in server.
#[derive(Debug, Clone, Copy)]
pub struct Builtin {
    /// Provider group the UI selects by: `cloudflare`, `hetzner`, `ovh`.
    pub group: &'static str,
    /// Server id, stable.
    pub id: &'static str,
    /// Display name.
    pub name: &'static str,
    /// Where it is.
    pub location: &'static str,
    /// Host name (port 443).
    pub host: &'static str,
    /// How to talk to it.
    pub kind: ServerKind,
    /// Static files of a mirror (empty for Cloudflare).
    pub files: &'static [MirrorFile],
    /// Most parallel connections the provider tolerates from one address; 0 = no limit known.
    pub max_streams: u32,
}

/// Every built-in server. Order is the display order.
pub const BUILTIN: &[Builtin] = &[
    Builtin {
        group: "cloudflare",
        id: "cloudflare",
        name: "Cloudflare",
        location: "Nearest edge",
        host: "speed.cloudflare.com",
        kind: ServerKind::Cloudflare,
        files: &[],
        max_streams: 0,
    },
    Builtin {
        group: "hetzner",
        id: "hetzner-fsn1",
        name: "Hetzner Falkenstein",
        location: "Falkenstein, DE",
        host: "fsn1-speed.hetzner.com",
        kind: ServerKind::Mirror,
        files: HETZNER_FILES,
        max_streams: 2,
    },
    Builtin {
        group: "hetzner",
        id: "hetzner-nbg1",
        name: "Hetzner Nuremberg",
        location: "Nuremberg, DE",
        host: "nbg1-speed.hetzner.com",
        kind: ServerKind::Mirror,
        files: HETZNER_FILES,
        max_streams: 2,
    },
    Builtin {
        group: "hetzner",
        id: "hetzner-hel1",
        name: "Hetzner Helsinki",
        location: "Helsinki, FI",
        host: "hel1-speed.hetzner.com",
        kind: ServerKind::Mirror,
        files: HETZNER_FILES,
        max_streams: 2,
    },
    Builtin {
        group: "hetzner",
        id: "hetzner-ash",
        name: "Hetzner Ashburn",
        location: "Ashburn, US",
        host: "ash-speed.hetzner.com",
        kind: ServerKind::Mirror,
        files: HETZNER_FILES,
        max_streams: 2,
    },
    Builtin {
        group: "hetzner",
        id: "hetzner-hil",
        name: "Hetzner Hillsboro",
        location: "Hillsboro, US",
        host: "hil-speed.hetzner.com",
        kind: ServerKind::Mirror,
        files: HETZNER_FILES,
        max_streams: 2,
    },
    Builtin {
        group: "hetzner",
        id: "hetzner-sin",
        name: "Hetzner Singapore",
        location: "Singapore, SG",
        host: "sin-speed.hetzner.com",
        kind: ServerKind::Mirror,
        files: HETZNER_FILES,
        max_streams: 2,
    },
    Builtin {
        group: "ovh",
        id: "ovh-gra",
        name: "OVHcloud Gravelines",
        location: "Gravelines, FR",
        host: "proof.ovh.net",
        kind: ServerKind::Mirror,
        files: OVH_FILES,
        max_streams: 3,
    },
];

/// The groups, in display order.
pub const GROUPS: &[&str] = &["cloudflare", "hetzner", "ovh"];

impl Builtin {
    /// The endpoint for this entry.
    pub fn endpoint(&self) -> ServerEndpoint {
        ServerEndpoint {
            id: self.id.to_owned(),
            name: self.name.to_owned(),
            scheme: Scheme::Https,
            host: self.host.to_owned(),
            port: 443,
            custom: false,
            kind: self.kind,
        }
    }
}

/// Built-in servers, optionally only one group (`None` = all of them).
pub fn builtin_servers(group: Option<&str>) -> Vec<ServerEndpoint> {
    BUILTIN
        .iter()
        .filter(|b| group.is_none_or(|g| b.group == g))
        .map(Builtin::endpoint)
        .collect()
}

/// The catalog entry behind a server, if it is a built-in one.
pub fn builtin_of(server: &ServerEndpoint) -> Option<&'static Builtin> {
    BUILTIN
        .iter()
        .find(|b| !server.custom && b.id == server.id && b.host == server.host)
}

/// Static files of a mirror server (empty for anything else).
pub fn mirror_files(server: &ServerEndpoint) -> &'static [MirrorFile] {
    match (server.kind, builtin_of(server)) {
        (ServerKind::Mirror, Some(b)) => b.files,
        _ => &[],
    }
}

/// The file to read `bytes` from: the smallest one that is large enough, else the largest.
pub fn pick_mirror_file(files: &[MirrorFile], bytes: u64) -> Option<MirrorFile> {
    files
        .iter()
        .filter(|f| f.bytes >= bytes)
        .min_by_key(|f| f.bytes)
        .or_else(|| files.iter().max_by_key(|f| f.bytes))
        .copied()
}

impl ServerEndpoint {
    /// Whether the server can take an upload test. Static mirrors cannot.
    pub fn supports_upload(&self) -> bool {
        self.kind != ServerKind::Mirror
    }

    /// Bytes of the largest bin test this server may be used for; `None` = no limit (a PacketWard speed
    /// server, the XeroHost nodes, the user's own). Public providers are limited so the app does not hammer
    /// a free service: Cloudflare takes none, Hetzner up to 10 GiB, OVH up to 1 GiB.
    pub fn bin_limit_bytes(&self) -> Option<u64> {
        match self.kind {
            ServerKind::Native => None,
            ServerKind::Cloudflare => Some(0),
            ServerKind::Mirror => Some(
                mirror_files(self)
                    .iter()
                    .map(|f| f.bytes)
                    .max()
                    .unwrap_or(0),
            ),
        }
    }

    /// Largest single request this server answers, when it has a limit of its own.
    pub fn max_request_bytes(&self) -> Option<u64> {
        match self.kind {
            ServerKind::Native => None,
            ServerKind::Cloudflare => Some(CLOUDFLARE_MAX_DOWNLOAD),
            ServerKind::Mirror => mirror_files(self).iter().map(|f| f.bytes).max(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_is_https_with_a_valid_host_and_a_unique_id() {
        let mut ids = std::collections::HashSet::new();
        for b in BUILTIN {
            let endpoint = b.endpoint();
            assert_eq!(endpoint.scheme, Scheme::Https);
            assert_eq!(endpoint.port, 443);
            assert!(ids.insert(b.id), "duplicate id {}", b.id);
            assert!(GROUPS.contains(&b.group));
            assert!(!endpoint.is_loopback());
            // Mirrors need files; Cloudflare needs none.
            assert_eq!(
                b.kind == ServerKind::Mirror,
                !b.files.is_empty(),
                "{}",
                b.id
            );
            assert!(!endpoint.custom);
        }
    }

    #[test]
    fn groups_select_their_own_servers() {
        assert_eq!(builtin_servers(None).len(), BUILTIN.len());
        let hetzner = builtin_servers(Some("hetzner"));
        assert_eq!(hetzner.len(), 6);
        assert!(hetzner.iter().all(|s| s.id.starts_with("hetzner-")));
        assert_eq!(builtin_servers(Some("cloudflare")).len(), 1);
        assert!(builtin_servers(Some("nope")).is_empty());
    }

    #[test]
    fn capabilities_follow_the_provider() {
        let cf = &builtin_servers(Some("cloudflare"))[0];
        assert!(cf.supports_upload());
        assert_eq!(cf.bin_limit_bytes(), Some(0));
        assert_eq!(cf.max_request_bytes(), Some(CLOUDFLARE_MAX_DOWNLOAD));
        let hz = &builtin_servers(Some("hetzner"))[0];
        assert!(!hz.supports_upload());
        assert_eq!(hz.bin_limit_bytes(), Some(10 * GIB));
        assert_eq!(hz.max_request_bytes(), Some(10 * GIB));
        let ovh = &builtin_servers(Some("ovh"))[0];
        assert_eq!(ovh.bin_limit_bytes(), Some(GIB));
        let own = ServerEndpoint::custom("https://speed.example.com").unwrap();
        assert!(own.supports_upload());
        assert_eq!(own.bin_limit_bytes(), None);
        assert_eq!(own.max_request_bytes(), None);
    }

    #[test]
    fn a_custom_server_cannot_pose_as_a_builtin() {
        let mut fake = builtin_servers(Some("hetzner"))[0].clone();
        fake.custom = true;
        assert!(builtin_of(&fake).is_none());
        assert!(mirror_files(&fake).is_empty());
    }

    #[test]
    fn the_smallest_file_that_fits_is_chosen() {
        let files = HETZNER_FILES;
        assert_eq!(
            pick_mirror_file(files, 50 * MIB).unwrap().path,
            "/100MB.bin"
        );
        assert_eq!(
            pick_mirror_file(files, 100 * MIB).unwrap().path,
            "/100MB.bin"
        );
        assert_eq!(pick_mirror_file(files, 101 * MIB).unwrap().path, "/1GB.bin");
        assert_eq!(pick_mirror_file(files, 20 * GIB).unwrap().path, "/10GB.bin");
        assert!(pick_mirror_file(&[], 1).is_none());
    }
}
