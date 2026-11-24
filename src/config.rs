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
        .and_then(|v| v.to_str().ok());
    let ip = visitor(peer.ip(), proxy, forwarded);
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
    fn empty_config() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c.listen.port(), 8461);
        assert!(toml::from_str::<Config>("typo = 1").is_err());
    }
}
