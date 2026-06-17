use anyhow::Context as _;

use crate::config::Config;

/// Self-probe for a container HEALTHCHECK: dial the running server's `{base_path}/healthz` over
/// std TCP (no HTTP-client crate) and `exit(0)` on a 200, `exit(1)` on any other status or failure
/// (server not up yet, connection refused, timeout). Mirrors the `Check` subcommand's exit style.
pub fn run(cfg: &Config) -> anyhow::Result<()> {
    std::process::exit(if probe(cfg).unwrap_or(false) { 0 } else { 1 });
}

/// `Ok(true)` only on a `200` status line; `Ok(false)` on any other status; `Err` on connect/IO
/// failure. A short timeout means a hung server fails the probe instead of hanging the healthcheck.
fn probe(cfg: &Config) -> anyhow::Result<bool> {
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    use std::time::Duration;

    let timeout = Duration::from_secs(5);
    let addr = probe_target(&cfg.listen)?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("connecting to {addr}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let req = format!(
        "GET {}/healthz HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        cfg.base_path
    );
    stream.write_all(req.as_bytes())?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp)?;
    Ok(resp
        .lines()
        .next()
        .is_some_and(|line| line.contains(" 200 ")))
}

/// Where to dial for the probe. A wildcard bind (`0.0.0.0` / `::`) can't be connected to, so rewrite
/// it to the matching loopback; otherwise dial the configured address (resolving a hostname:port).
fn probe_target(listen: &str) -> anyhow::Result<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _};
    if let Ok(addr) = listen.parse::<SocketAddr>() {
        if addr.ip().is_unspecified() {
            let loopback: IpAddr = match addr.ip() {
                IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
                IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
            };
            return Ok(SocketAddr::new(loopback, addr.port()));
        }
        return Ok(addr);
    }
    listen
        .to_socket_addrs()?
        .next()
        .with_context(|| format!("`{listen}` did not resolve to an address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthz_probe_rewrites_wildcard_to_loopback() {
        // Wildcard binds aren't dialable → rewrite to loopback of the same family, port intact.
        assert_eq!(t("0.0.0.0:52155"), "127.0.0.1:52155");
        assert_eq!(t("[::]:52155"), "[::1]:52155");
        // Concrete addresses are dialed as-is.
        assert_eq!(t("127.0.0.1:52155"), "127.0.0.1:52155");
        assert_eq!(t("192.168.1.5:8080"), "192.168.1.5:8080");
    }

    fn t(listen: &str) -> String {
        probe_target(listen).unwrap().to_string()
    }
}
