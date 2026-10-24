//! Finding the Core on the local network with mDNS / DNS-SD (ADR-0024),
//! as Nepheral does with `mdns-sd`.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

pub const CORE_SERVICE: &str = "_hawk-core._udp.local.";

/// A Core seen on the network.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Found {
    pub instance: String,
    pub addrs: Vec<SocketAddr>,
    pub txt: HashMap<String, String>,
}

/// Keeps an announcement alive while it is held.
pub struct Announcement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl std::fmt::Debug for Announcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Announcement")
            .field("fullname", &self.fullname)
            .finish()
    }
}

impl Drop for Announcement {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Announces `instance` on `port` with `txt` records. Replacing the TXT
/// (for example when the Core gets paired) means announcing again.
pub fn announce(instance: &str, port: u16, txt: &[(&str, String)]) -> Result<Announcement, String> {
    let daemon = ServiceDaemon::new().map_err(|e| e.to_string())?;
    let ip = local_ip_address::local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let props: HashMap<String, String> = txt
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    let info = ServiceInfo::new(
        CORE_SERVICE,
        instance,
        &format!("{instance}.local."),
        ip,
        port,
        props,
    )
    .map_err(|e| e.to_string())?;
    let fullname = info.get_fullname().to_owned();
    daemon.register(info).map_err(|e| e.to_string())?;
    Ok(Announcement { daemon, fullname })
}

/// Browses for Cores for `wait` and returns what answered.
pub fn browse(wait: Duration) -> Result<Vec<Found>, String> {
    let daemon = ServiceDaemon::new().map_err(|e| e.to_string())?;
    let receiver = daemon.browse(CORE_SERVICE).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + wait;
    let mut found: HashMap<String, Found> = HashMap::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match receiver.recv_timeout(left) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let port = info.get_port();
                let mut addrs: Vec<SocketAddr> = info
                    .get_addresses()
                    .iter()
                    .map(|a| SocketAddr::new(*a, port))
                    .collect();
                addrs.sort_by_key(|a| !a.is_ipv4());
                let txt = info
                    .get_properties()
                    .iter()
                    .map(|p| (p.key().to_owned(), p.val_str().to_owned()))
                    .collect();
                let instance = info
                    .get_fullname()
                    .trim_end_matches(CORE_SERVICE)
                    .trim_end_matches('.')
                    .to_owned();
                found.insert(
                    instance.clone(),
                    Found {
                        instance,
                        addrs,
                        txt,
                    },
                );
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.shutdown();
    Ok(found.into_values().collect())
}
