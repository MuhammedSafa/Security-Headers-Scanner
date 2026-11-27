use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use url::{Host, Url};

#[derive(Debug, Error)]
pub enum SsrfError {
    #[error("Only http and https URL schemes are allowed")]
    UnsupportedScheme,
    #[error("URL must not contain embedded credentials")]
    EmbeddedCredentials,
    #[error("URL is missing a valid host")]
    MissingHost,
    #[error("Target resolves to a blocked private/internal IP address: {0}")]
    BlockedIp(IpAddr),
    #[error("Target hostname is blocked by SSRF policy: {0}")]
    BlockedHost(String),
    #[error("DNS resolution failed for {host}: {source}")]
    DnsResolution { host: String, source: io::Error },
    #[error("DNS resolution returned no addresses for {0}")]
    EmptyDnsResult(String),
}

/// Returns `true` if `ip` is loopback, private (RFC1918/ULA), link-local (including
/// cloud metadata 169.254.169.254), CGNAT, multicast, broadcast, documentation, or reserved.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_ipv4(v4),
        IpAddr::V6(v6) => is_forbidden_ipv6(v6),
    }
}

fn is_forbidden_ipv4(v4: Ipv4Addr) -> bool {
    let oct = v4.octets();
    v4.is_unspecified() // 0.0.0.0/8
        || oct[0] == 0
        || v4.is_loopback() // 127.0.0.0/8
        || v4.is_private() // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || v4.is_link_local() // 169.254.0.0/16 (AWS/GCP/Azure metadata)
        || v4.is_broadcast() // 255.255.255.255
        || v4.is_multicast() // 224.0.0.0/4
        || v4.is_documentation() // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        || (oct[0] == 100 && (oct[1] & 0b1100_0000) == 64) // 100.64.0.0/10 CGNAT
        || (oct[0] == 192 && oct[1] == 0 && oct[2] == 0) // 192.0.0.0/24 IETF protocol
        || (oct[0] == 198 && (oct[1] == 18 || oct[1] == 19)) // 198.18.0.0/15 benchmarking
        || oct[0] >= 240 // 240.0.0.0/4 reserved
}

fn is_forbidden_ipv6(v6: Ipv6Addr) -> bool {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return is_forbidden_ipv4(mapped);
    }
    let seg = v6.segments();
    v6.is_unspecified() // ::
        || v6.is_loopback() // ::1
        || v6.is_multicast() // ff00::/8
        || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 Unique Local
        || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 Link-local
        || (seg[0] & 0xffc0) == 0xfec0 // fec0::/10 Deprecated site-local
        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // 2001:db8::/32 Documentation
        || (seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0 && (seg[6] != 0 || seg[7] != 0))
    // IPv4-compatible ::w.x.y.z
}

pub fn validate_url(url: &Url, allow_private_networks: bool) -> Result<(), SsrfError> {
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err(SsrfError::UnsupportedScheme),
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(SsrfError::EmbeddedCredentials);
    }

    let host = url.host().ok_or(SsrfError::MissingHost)?;
    if !allow_private_networks {
        match host {
            Host::Ipv4(v4) => {
                let ip = IpAddr::V4(v4);
                if is_forbidden_ip(ip) {
                    return Err(SsrfError::BlockedIp(ip));
                }
            }
            Host::Ipv6(v6) => {
                let ip = IpAddr::V6(v6);
                if is_forbidden_ip(ip) {
                    return Err(SsrfError::BlockedIp(ip));
                }
            }
            Host::Domain(domain) => {
                let lower = domain.trim_end_matches('.').to_ascii_lowercase();
                if lower == "localhost"
                    || lower.ends_with(".localhost")
                    || lower.ends_with(".local")
                    || lower.ends_with(".internal")
                {
                    return Err(SsrfError::BlockedHost(domain.to_string()));
                }
            }
        }
    }

    Ok(())
}

/// Custom `reqwest` DNS resolver that validates every resolved IP address before a TCP
/// connection is established, protecting against both direct SSRF and DNS rebinding.
#[derive(Debug, Clone)]
pub struct SsrfSafeResolver {
    pub allow_private_networks: bool,
}

impl Resolve for SsrfSafeResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allow_private = self.allow_private_networks;
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(SsrfError::DnsResolution {
                        host: host.clone(),
                        source: e,
                    })
                })?
                .collect();

            if addrs.is_empty() {
                return Err(Box::new(SsrfError::EmptyDnsResult(host))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            if !allow_private {
                for addr in &addrs {
                    if is_forbidden_ip(addr.ip()) {
                        return Err(Box::new(SsrfError::BlockedIp(addr.ip()))
                            as Box<dyn std::error::Error + Send + Sync>);
                    }
                }
            }

            let iter: Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn blocks_private_loopback_and_metadata_ips() {
        let blocked = [
            "0.0.0.0",
            "127.0.0.1",
            "127.0.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.5",
        ];

        for raw in blocked {
            let ip = IpAddr::from_str(raw).unwrap();
            assert!(is_forbidden_ip(ip), "Expected {raw} to be blocked");
        }
    }

    #[test]
    fn allows_public_ips() {
        let allowed = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.32.0.1",
            "100.128.0.1",
            "2606:2800:220:1:248:1893:25c8:1946",
        ];

        for raw in allowed {
            let ip = IpAddr::from_str(raw).unwrap();
            assert!(!is_forbidden_ip(ip), "Expected {raw} to be allowed");
        }
    }

    #[test]
    fn validates_urls_and_respects_allow_private_flag() {
        let meta = Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        assert!(validate_url(&meta, false).is_err());
        assert!(validate_url(&meta, true).is_ok());

        let local = Url::parse("http://localhost:8080/").unwrap();
        assert!(validate_url(&local, false).is_err());
        assert!(validate_url(&local, true).is_ok());

        let creds = Url::parse("https://user:pass@example.com/").unwrap();
        assert!(matches!(
            validate_url(&creds, true),
            Err(SsrfError::EmbeddedCredentials)
        ));

        let ftp = Url::parse("ftp://example.com/").unwrap();
        assert!(matches!(
            validate_url(&ftp, true),
            Err(SsrfError::UnsupportedScheme)
        ));

        let public = Url::parse("https://example.com/app").unwrap();
        assert!(validate_url(&public, false).is_ok());
    }
}
