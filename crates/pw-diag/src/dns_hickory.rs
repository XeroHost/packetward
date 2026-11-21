// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
//! The real [`DnsBackend`], built on `hickory-resolver` (plain UDP with TCP fallback, no TLS).
//! No hickory type appears in this crate's public API.

use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};

use crate::dns::{
    DnsBackend, DnsClient, DnsFailure, DnsOptions, DnsRecord, DnsRecordData, DnsRecordType,
    ResolverChoice, MAX_DNS_TIMEOUT, MIN_DNS_TIMEOUT,
};

/// Resolver backed by `hickory-resolver`. Caching is disabled and the hosts file is ignored, so
/// every query really goes to the chosen servers.
pub struct HickoryBackend {
    resolver: TokioResolver,
}

impl std::fmt::Debug for HickoryBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryBackend").finish_non_exhaustive()
    }
}

impl HickoryBackend {
    /// Build a resolver for `choice` with the given per-query timeout (one attempt per query).
    pub fn new(choice: &ResolverChoice, timeout: Duration) -> Result<Self, DnsFailure> {
        let timeout = timeout.clamp(MIN_DNS_TIMEOUT, MAX_DNS_TIMEOUT);
        let servers = choice.servers()?;
        let mut builder = match servers {
            None => Resolver::builder(TokioRuntimeProvider::default()).map_err(|e| {
                DnsFailure::Config(format!("cannot read the system DNS settings: {e}"))
            })?,
            Some(ips) => {
                let name_servers = ips.into_iter().map(NameServerConfig::udp_and_tcp).collect();
                Resolver::builder_with_config(
                    ResolverConfig::from_name_servers(name_servers),
                    TokioRuntimeProvider::default(),
                )
            }
        };
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = 1;
        opts.cache_size = 0;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.try_tcp_on_error = true;
        let resolver = builder
            .build()
            .map_err(|e| DnsFailure::Config(format!("cannot build the resolver: {e}")))?;
        Ok(Self { resolver })
    }
}

impl DnsClient<HickoryBackend> {
    /// A client for `options` (resolver choice and timeout).
    pub fn with_options(options: &DnsOptions) -> Result<Self, DnsFailure> {
        let timeout = options.effective_timeout();
        Ok(DnsClient::new(
            HickoryBackend::new(&options.resolver, timeout)?,
            timeout,
        ))
    }
}

impl DnsBackend for HickoryBackend {
    async fn query(
        &self,
        name: &str,
        record_type: DnsRecordType,
    ) -> Result<Vec<DnsRecord>, DnsFailure> {
        let Some(wire_type) = wire_type(record_type) else {
            return Err(DnsFailure::Other(
                "ALL is expanded before the backend is called".to_owned(),
            ));
        };
        match self.resolver.lookup(name, wire_type).await {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| {
                    convert(&r.data).map(|data| DnsRecord {
                        name: trim_root(&r.name.to_utf8()),
                        ttl: r.ttl,
                        data,
                    })
                })
                // A CNAME chain comes back together with the final records; keep only what was asked.
                .filter(|r| r.record_type() == record_type)
                .collect()),
            Err(e) => map_error(&e),
        }
    }
}

fn wire_type(t: DnsRecordType) -> Option<RecordType> {
    Some(match t {
        DnsRecordType::A => RecordType::A,
        DnsRecordType::Aaaa => RecordType::AAAA,
        DnsRecordType::Mx => RecordType::MX,
        DnsRecordType::Txt => RecordType::TXT,
        DnsRecordType::Ns => RecordType::NS,
        DnsRecordType::Soa => RecordType::SOA,
        DnsRecordType::Cname => RecordType::CNAME,
        DnsRecordType::Ptr => RecordType::PTR,
        DnsRecordType::All => return None,
    })
}

fn trim_root(name: &str) -> String {
    match name.strip_suffix('.') {
        Some(rest) if !rest.is_empty() => rest.to_owned(),
        _ => name.to_owned(),
    }
}

fn convert(data: &RData) -> Option<DnsRecordData> {
    Some(match data {
        RData::A(a) => DnsRecordData::A(a.0),
        RData::AAAA(a) => DnsRecordData::Aaaa(a.0),
        RData::MX(mx) => DnsRecordData::Mx {
            preference: mx.preference,
            exchange: trim_root(&mx.exchange.to_utf8()),
        },
        RData::TXT(txt) => DnsRecordData::Txt(
            txt.txt_data
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk))
                .collect::<Vec<_>>()
                .concat(),
        ),
        RData::NS(ns) => DnsRecordData::Ns(trim_root(&ns.0.to_utf8())),
        RData::SOA(soa) => DnsRecordData::Soa {
            mname: trim_root(&soa.mname.to_utf8()),
            rname: trim_root(&soa.rname.to_utf8()),
            serial: soa.serial,
            refresh: soa.refresh,
            retry: soa.retry,
            expire: soa.expire,
            minimum: soa.minimum,
        },
        RData::CNAME(c) => DnsRecordData::Cname(trim_root(&c.0.to_utf8())),
        RData::PTR(p) => DnsRecordData::Ptr(trim_root(&p.0.to_utf8())),
        _ => return None,
    })
}

/// Translate a resolver error. "No records of that type" is a success with an empty list;
/// NXDOMAIN, SERVFAIL, REFUSED and timeouts keep their identity.
fn map_error(e: &NetError) -> Result<Vec<DnsRecord>, DnsFailure> {
    match e {
        NetError::Dns(DnsError::NoRecordsFound(no)) => match no.response_code {
            ResponseCode::NXDomain => Err(DnsFailure::NxDomain),
            ResponseCode::NoError => Ok(Vec::new()),
            ResponseCode::ServFail => Err(DnsFailure::ServFail),
            ResponseCode::Refused => Err(DnsFailure::Refused),
            other => Err(DnsFailure::Other(format!("DNS response code {other}"))),
        },
        NetError::Dns(DnsError::ResponseCode(code)) => match code {
            ResponseCode::NXDomain => Err(DnsFailure::NxDomain),
            ResponseCode::ServFail => Err(DnsFailure::ServFail),
            ResponseCode::Refused => Err(DnsFailure::Refused),
            other => Err(DnsFailure::Other(format!("DNS response code {other}"))),
        },
        NetError::Timeout => Err(DnsFailure::Timeout),
        NetError::Io(io) => Err(DnsFailure::Network(io.to_string())),
        NetError::NoConnections | NetError::Busy => Err(DnsFailure::Network(e.to_string())),
        other => Err(DnsFailure::Other(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::net::NoRecords;
    use hickory_resolver::proto::op::Query;
    use std::sync::Arc;

    fn no_records(code: ResponseCode) -> NetError {
        NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            Query::default(),
            code,
        )))
    }

    #[test]
    fn maps_resolver_errors() {
        assert_eq!(
            map_error(&no_records(ResponseCode::NXDomain)),
            Err(DnsFailure::NxDomain)
        );
        assert_eq!(map_error(&no_records(ResponseCode::NoError)), Ok(vec![]));
        assert_eq!(
            map_error(&no_records(ResponseCode::ServFail)),
            Err(DnsFailure::ServFail)
        );
        assert_eq!(map_error(&NetError::Timeout), Err(DnsFailure::Timeout));
        assert_eq!(
            map_error(&NetError::Dns(DnsError::ResponseCode(
                ResponseCode::ServFail
            ))),
            Err(DnsFailure::ServFail)
        );
        assert_eq!(
            map_error(&NetError::Dns(DnsError::ResponseCode(
                ResponseCode::Refused
            ))),
            Err(DnsFailure::Refused)
        );
        assert_eq!(
            map_error(&NetError::Dns(DnsError::ResponseCode(
                ResponseCode::NXDomain
            ))),
            Err(DnsFailure::NxDomain)
        );
        assert!(matches!(
            map_error(&NetError::Io(Arc::new(std::io::Error::other("boom")))),
            Err(DnsFailure::Network(_))
        ));
        assert!(matches!(
            map_error(&NetError::NoConnections),
            Err(DnsFailure::Network(_))
        ));
        assert!(matches!(
            map_error(&NetError::Msg("x".into())),
            Err(DnsFailure::Other(_))
        ));
    }

    #[test]
    fn converts_rdata() {
        use hickory_resolver::proto::rr::rdata::{A, MX, TXT};
        use hickory_resolver::proto::rr::Name;
        assert_eq!(
            convert(&RData::A(A("192.0.2.1".parse().unwrap()))),
            Some(DnsRecordData::A("192.0.2.1".parse().unwrap()))
        );
        let mx = MX::new(5, Name::from_ascii("mail.example.com.").unwrap());
        assert_eq!(
            convert(&RData::MX(mx)),
            Some(DnsRecordData::Mx {
                preference: 5,
                exchange: "mail.example.com".into()
            })
        );
        let txt = TXT::new(vec!["v=spf1 ".to_owned(), "-all".to_owned()]);
        assert_eq!(
            convert(&RData::TXT(txt)),
            Some(DnsRecordData::Txt("v=spf1 -all".into()))
        );
    }

    #[test]
    fn trims_only_the_root_dot() {
        assert_eq!(trim_root("example.com."), "example.com");
        assert_eq!(trim_root("."), ".");
        assert_eq!(trim_root("example.com"), "example.com");
    }

    #[test]
    fn all_has_no_wire_type() {
        assert!(wire_type(DnsRecordType::All).is_none());
        for t in DnsRecordType::CONCRETE {
            assert!(wire_type(t).is_some());
        }
    }

    #[tokio::test]
    async fn custom_resolver_builds_without_network() {
        let b = HickoryBackend::new(
            &ResolverChoice::Custom(vec!["127.0.0.1".parse().unwrap()]),
            Duration::from_millis(300),
        );
        assert!(b.is_ok());
        assert!(matches!(
            HickoryBackend::new(&ResolverChoice::Custom(vec![]), Duration::from_secs(1)),
            Err(DnsFailure::Config(_))
        ));
    }

    /// Needs the internet and working system DNS: `cargo test -p pw-diag -- --ignored dns_live`.
    #[tokio::test]
    #[ignore = "queries the system DNS servers"]
    async fn dns_live_system_resolver_and_nxdomain() {
        let client = DnsClient::with_options(&DnsOptions::default()).unwrap();
        let ok = client
            .lookup("example.com", DnsRecordType::A)
            .await
            .unwrap();
        assert!(!ok.records.is_empty());
        let gone = client
            .lookup("pw-diag-no-such-name.example.invalid", DnsRecordType::A)
            .await;
        assert_eq!(gone, Err(DnsFailure::NxDomain));
        let ptr = client.lookup("1.1.1.1", DnsRecordType::Ptr).await.unwrap();
        assert!(ptr
            .records
            .iter()
            .all(|r| r.record_type() == DnsRecordType::Ptr));
    }

    /// Needs the internet: `cargo test -p pw-diag -- --ignored dns_live`.
    #[tokio::test]
    #[ignore = "queries live DNS servers"]
    async fn dns_live_all_on_example_com() {
        let client = DnsClient::with_options(&DnsOptions {
            resolver: ResolverChoice::Cloudflare,
            timeout: Duration::from_secs(5),
        })
        .unwrap();
        let r = client
            .lookup("example.com", DnsRecordType::All)
            .await
            .unwrap();
        assert!(r
            .records
            .iter()
            .any(|x| x.record_type() == DnsRecordType::A));
        assert!(r
            .records
            .iter()
            .any(|x| x.record_type() == DnsRecordType::Ns));
        assert!(r
            .records
            .iter()
            .any(|x| x.record_type() == DnsRecordType::Soa));
    }
}
