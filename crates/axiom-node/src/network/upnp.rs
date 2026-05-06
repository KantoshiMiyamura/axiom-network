// Copyright (c) 2026 Kantoshi Miyamura

//! UPnP (IGD) port-forward helper. Stage 8 of `docs/V2_PROTOCOL.md §8`.
//!
//! Best-effort: a v2-dev node attempts to ask its LAN router (via the
//! Internet Gateway Device protocol) to forward inbound TCP traffic on
//! the node's P2P port to its local LAN address. The mapping is leased
//! for [`DEFAULT_LEASE_SECS`]; the renewal task re-requests it before
//! expiry. Every failure mode is non-fatal and yields a clear log line
//! plus a manual port-forward instruction string the operator can copy
//! into the router admin UI.
//!
//! INVARIANT: this module is **not** required for node correctness. A
//! node whose router does not speak UPnP, or whose UPnP request is
//! refused, runs as outbound-only — still fully functional, just not
//! reachable from the internet. The CLI flag `--no-upnp` disables the
//! attempt entirely for operators who do not want SSDP traffic on
//! their LAN.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use tokio::sync::RwLock;
use tokio::time;

/// Default lease duration for the IGD port mapping. One hour is the
/// canonical value in the IGD spec — long enough to ride out brief
/// network blips, short enough to clean up after a node crash.
pub const DEFAULT_LEASE_SECS: u32 = 3600;

/// Renew slightly before the lease ends so a router that ages out
/// "expired" mappings aggressively never serves a stale state.
pub const RENEW_BEFORE_EXPIRY_SECS: u64 = 5 * 60;

/// SSDP search timeout — discovery is best-effort; if the router does
/// not answer in this window, treat it as "no UPnP-capable device".
pub const SEARCH_TIMEOUT_SECS: u64 = 4;

/// Description string the router shows to the user in its admin UI.
pub const MAPPING_DESCRIPTION: &str = "axiom-node v2";

/// Live state for an active UPnP port mapping.
#[derive(Clone, Debug)]
pub struct UpnpMapping {
    pub external_ip: IpAddr,
    pub external_port: u16,
    pub local_port: u16,
    pub lease_secs: u32,
}

impl UpnpMapping {
    /// Render the external socket address as `IP:port` for log lines
    /// and the `axiom status` CLI.
    pub fn external_address(&self) -> String {
        match self.external_ip {
            IpAddr::V4(_) => format!("{}:{}", self.external_ip, self.external_port),
            IpAddr::V6(_) => format!("[{}]:{}", self.external_ip, self.external_port),
        }
    }
}

/// Shared handle the runtime passes around. `None` until the first
/// successful map, then carries the live mapping. The renewal task
/// updates the inner value on each successful renew.
pub type SharedUpnpMapping = Arc<RwLock<Option<UpnpMapping>>>;

#[derive(Error, Debug)]
pub enum UpnpError {
    #[error(
        "no UPnP-capable router found on the LAN within {SEARCH_TIMEOUT_SECS}s — \
         either the router has UPnP/IGD disabled, or no IGD device is reachable"
    )]
    NoGateway,

    #[error("could not determine the local LAN IP for this node")]
    NoLocalIp,

    #[error(
        "router accepted SSDP discovery but refused the port-mapping request: {0}. \
         The router may be configured to ignore UPnP requests from clients."
    )]
    MappingRefused(String),

    #[error("could not query the router for the external IP: {0}")]
    GetExternalIpFailed(String),

    #[error("UPnP search underlying error: {0}")]
    Search(String),
}

/// Discover the LAN IGD, ask for a TCP port mapping for `local_port`,
/// and return the resulting [`UpnpMapping`] on success. The mapping is
/// leased for `lease_secs` seconds — the caller is expected to spawn
/// a renewal task (see [`spawn_renewal_task`]) to keep it alive.
pub async fn try_map(local_port: u16, lease_secs: u32) -> Result<UpnpMapping, UpnpError> {
    use igd_next::aio::tokio::search_gateway;
    use igd_next::PortMappingProtocol;
    use igd_next::SearchOptions;

    let local_ip = detect_local_ipv4().ok_or(UpnpError::NoLocalIp)?;
    let local_socket = SocketAddrV4::new(local_ip, local_port);

    let search_opts = SearchOptions {
        timeout: Some(Duration::from_secs(SEARCH_TIMEOUT_SECS)),
        ..Default::default()
    };

    let gateway = match time::timeout(
        Duration::from_secs(SEARCH_TIMEOUT_SECS + 1),
        search_gateway(search_opts),
    )
    .await
    {
        Ok(Ok(g)) => g,
        Ok(Err(e)) => return Err(UpnpError::Search(format!("{e:?}"))),
        Err(_) => return Err(UpnpError::NoGateway),
    };

    let external_ip = gateway
        .get_external_ip()
        .await
        .map_err(|e| UpnpError::GetExternalIpFailed(format!("{e:?}")))?;

    gateway
        .add_port(
            PortMappingProtocol::TCP,
            local_port,
            local_socket.into(),
            lease_secs,
            MAPPING_DESCRIPTION,
        )
        .await
        .map_err(|e| UpnpError::MappingRefused(format!("{e:?}")))?;

    Ok(UpnpMapping {
        external_ip,
        external_port: local_port,
        local_port,
        lease_secs,
    })
}

/// Best-effort `remove_port` for graceful shutdown. Errors are
/// swallowed — if the router is unreachable at shutdown, the lease
/// will simply expire on its own.
pub async fn try_unmap(local_port: u16) {
    use igd_next::aio::tokio::search_gateway;
    use igd_next::PortMappingProtocol;
    use igd_next::SearchOptions;

    let search_opts = SearchOptions {
        timeout: Some(Duration::from_secs(SEARCH_TIMEOUT_SECS)),
        ..Default::default()
    };

    let gateway = match time::timeout(
        Duration::from_secs(SEARCH_TIMEOUT_SECS + 1),
        search_gateway(search_opts),
    )
    .await
    {
        Ok(Ok(g)) => g,
        _ => return,
    };
    let _ = gateway
        .remove_port(PortMappingProtocol::TCP, local_port)
        .await;
}

/// Spawn a tokio task that renews the mapping ~5 minutes before lease
/// expiry. The task updates `state` on every successful renew and logs
/// a `WARN` line on every failure (without exiting — a transient
/// router blip should not kill the renewal loop).
pub fn spawn_renewal_task(state: SharedUpnpMapping, local_port: u16, lease_secs: u32) {
    let renew_interval = Duration::from_secs(
        lease_secs
            .saturating_sub(RENEW_BEFORE_EXPIRY_SECS as u32)
            .max(60) as u64,
    );

    tokio::spawn(async move {
        loop {
            time::sleep(renew_interval).await;
            match try_map(local_port, lease_secs).await {
                Ok(mapping) => {
                    tracing::info!(
                        "UPnP renew: external = {}, lease = {}s",
                        mapping.external_address(),
                        mapping.lease_secs
                    );
                    *state.write().await = Some(mapping);
                }
                Err(e) => {
                    tracing::warn!(
                        "UPnP renew failed (mapping may expire on the router): {e}. \
                         The node continues to run — outbound peer dialing is unaffected."
                    );
                }
            }
        }
    });
}

/// Manual port-forward instructions for operators whose router does
/// not speak UPnP. Returned as a multi-line string the runtime prints
/// once after a UPnP failure.
pub fn fallback_instructions(local_port: u16) -> String {
    format!(
        "─────────────────────────────────────────────────────────────\n\
         UPnP unavailable — manual port-forward needed for inbound peers\n\
         ─────────────────────────────────────────────────────────────\n\
         The node will still run and dial outbound peers. To accept\n\
         inbound connections, open the router's admin page (commonly\n\
         http://192.168.1.1 or http://192.168.0.1) and add:\n\
         \n\
         Protocol: TCP\n\
         External port: {local_port}\n\
         Internal port: {local_port}\n\
         Internal IP: this node's LAN address (often 192.168.x.x)\n\
         \n\
         Once the rule is saved, restart the node and run\n\
         `axiom status` to confirm the external mapping shows up.\n\
         ─────────────────────────────────────────────────────────────"
    )
}

/// Detect this host's LAN IPv4 address by asking the OS which IP it
/// would source-bind for a route to a public destination. No network
/// traffic is actually sent — `connect` on a UDP socket only updates
/// the kernel's route cache. Returns `None` when the host has no
/// outbound IPv4 route (rare but possible on IPv6-only or air-gapped
/// machines).
fn detect_local_ipv4() -> Option<Ipv4Addr> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let local: SocketAddr = socket.local_addr().ok()?;
    match local.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// `external_address()` formats IPv4 as `ip:port` and IPv6 in the
    /// bracketed `[ip]:port` form (matching the convention in
    /// `axiom-cli` and most explorer URLs).
    #[test]
    fn external_address_formatting_ipv4_and_ipv6() {
        let m_v4 = UpnpMapping {
            external_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            external_port: 9000,
            local_port: 9000,
            lease_secs: 3600,
        };
        assert_eq!(m_v4.external_address(), "203.0.113.5:9000");

        let m_v6 = UpnpMapping {
            external_ip: "2001:db8::1".parse().unwrap(),
            external_port: 9000,
            local_port: 9000,
            lease_secs: 3600,
        };
        assert_eq!(m_v6.external_address(), "[2001:db8::1]:9000");
    }

    /// Fallback instructions mention the port the operator must forward
    /// and the canonical router-admin URLs. Pin the format so a future
    /// rewrite of the message does not silently drop one of the bits
    /// the user needs to act on.
    #[test]
    fn fallback_instructions_mention_the_port_and_protocol() {
        let s = fallback_instructions(9000);
        assert!(s.contains("9000"), "must name the port: {s}");
        assert!(s.contains("TCP"), "must specify protocol: {s}");
        assert!(s.contains("router"), "must reference the router: {s}");
        // No private-address claim that we cannot back up — the message
        // should suggest "192.168.x.x" rather than asserting it.
        assert!(s.contains("192.168"), "must hint at private IP form: {s}");
    }

    /// `UpnpError` Display strings carry enough context that an operator
    /// reading the log can act on them without the source.
    #[test]
    fn upnp_error_messages_are_actionable() {
        let no_gw = UpnpError::NoGateway.to_string();
        assert!(no_gw.contains("UPnP"));
        assert!(no_gw.contains("router") || no_gw.contains("IGD"));

        let refused = UpnpError::MappingRefused("not authorized".into()).to_string();
        assert!(refused.contains("not authorized"));
        assert!(refused.contains("router"));
    }

    /// `detect_local_ipv4` returns either a non-unspecified IPv4 (the
    /// common case on any host with a default route) or `None` (no
    /// outbound IPv4). It must never panic. We only assert the
    /// non-panicking property because CI environments without IPv4
    /// connectivity still need to pass this test.
    #[test]
    fn detect_local_ipv4_does_not_panic() {
        let _ = detect_local_ipv4();
        // Either Some(non-unspecified) or None — anything else is a bug.
        if let Some(ip) = detect_local_ipv4() {
            assert!(!ip.is_unspecified());
        }
    }

    /// Sanity check on the renewal-interval math: with a 1-hour lease
    /// and a 5-minute pre-expiry buffer, the loop sleeps 55 minutes
    /// between renew attempts.
    #[test]
    fn renewal_interval_math_default_lease() {
        let lease = DEFAULT_LEASE_SECS;
        let buf = RENEW_BEFORE_EXPIRY_SECS as u32;
        let interval_secs = lease.saturating_sub(buf).max(60);
        assert_eq!(interval_secs, 3300, "1h lease - 5min buffer = 55min");
    }

    /// Edge case: a pathologically short lease (under 5 minutes) is
    /// clamped to a 60-second floor so the renewal loop does not busy-
    /// retry, even if the operator (or router) imposes a tiny lease.
    #[test]
    fn renewal_interval_clamps_to_at_least_60s() {
        let lease: u32 = 30; // shorter than the 5-min pre-expiry buffer
        let buf = RENEW_BEFORE_EXPIRY_SECS as u32;
        let interval_secs = lease.saturating_sub(buf).max(60);
        assert_eq!(interval_secs, 60);
    }
}
