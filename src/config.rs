//! `server.toml` in the data directory. Optional.

use anyhow::{Context, Result};
use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// A reverse proxy with a publicly trusted certificate. Only its X-Forwarded-For
    /// is believed.
    pub trusted_proxy: Option<IpAddr>,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], sundial_link::DEFAULT_PORT))
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        toml::from_str(&text).with_context(|| format!("reading {}", path.display()))
    }
}

/// The visitor's address: the last X-Forwarded-For entry, the one the proxy added
/// itself, if the trusted proxy sent the request.
fn visitor(peer: IpAddr, proxy: Option<IpAddr>, forwarded: Option<&str>) -> IpAddr {
    if proxy != Some(peer.to_canonical()) {
        return peer;
    }
    forwarded
        .and_then(|f| f.rsplit(',').next())
        .and_then(|a| a.trim().parse().ok())
        .unwrap_or(peer)
}

/// The visitor is certainly on this network. Set on every request.
#[derive(Clone, Copy)]
pub struct AtHome(pub bool);

/// Addresses that can only be on this network.
fn local(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local(),
        IpAddr::V6(a) => a.is_loopback() || a.is_unique_local() || a.is_unicast_link_local(),
    }
}

/// Behind a proxy we don't know, or one that doesn't say who is visiting, nobody is.
fn at_home(peer: IpAddr, proxy: Option<IpAddr>, forwarded: Option<&str>) -> bool {
    match (proxy == Some(peer.to_canonical()), forwarded) {
        (true, Some(f)) => f
            .rsplit(',')
            .next()
            .and_then(|a| a.trim().parse().ok())
            .is_some_and(local),
        (true, None) | (false, Some(_)) => false,
        (false, None) => local(peer),
    }
}

/// Make the sign-in lockout count visitors, not the proxy.
pub async fn real_ip(
    State(proxy): State<Option<IpAddr>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let forwarded = req
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .map(|v| v.to_str().unwrap_or(""));
    let home = at_home(peer.ip(), proxy, forwarded) && !req.headers().contains_key("forwarded");
    let ip = visitor(peer.ip(), proxy, forwarded);
    req.extensions_mut().insert(AtHome(home));
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(ip, peer.port())));
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_proxy_is_believed() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let (p, x) = (ip("192.0.2.1"), ip("192.0.2.9"));
        assert_eq!(visitor(x, Some(p), Some("1.1.1.1")), x);
        assert_eq!(visitor(x, None, Some("1.1.1.1")), x);
        assert_eq!(visitor(p, Some(p), Some("6.6.6.6, 1.1.1.1")), ip("1.1.1.1"));
        assert_eq!(visitor(p, Some(p), Some("junk")), p);
        assert_eq!(visitor(p, Some(p), None), p);
    }

    #[test]
    fn home_addresses() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for a in [
            "192.168.1.2",
            "10.0.0.1",
            "127.0.0.1",
            "::1",
            "fd00::2",
            "::ffff:10.1.1.1",
        ] {
            assert!(at_home(ip(a), None, None), "{a}");
        }
        for a in ["8.8.8.8", "100.64.0.1", "2606:4700::1", "::ffff:8.8.8.8"] {
            assert!(!at_home(ip(a), None, None), "{a}");
        }
        let p = ip("10.0.0.9");
        assert!(at_home(p, Some(p), Some("8.8.8.8, 10.0.0.5")));
        assert!(!at_home(p, Some(p), Some("10.0.0.5, 8.8.8.8")));
        assert!(!at_home(p, Some(p), None));
        assert!(!at_home(p, Some(p), Some("junk")));
        assert!(!at_home(p, None, Some("10.0.0.5")), "unknown proxy");
    }

    #[test]
    fn empty_config() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c.listen.port(), 8461);
        assert!(toml::from_str::<Config>("typo = 1").is_err());
    }
}
