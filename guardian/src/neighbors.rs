//! The MAC of a peer, from the Core's own neighbour table (ADR-0028). A
//! value the Core observes, unlike anything a host declares, so it may be a
//! containment target.
//!
//! Only peers on the same L2 segment have one: behind a router the table
//! holds the router's MAC under the router's address, never under the
//! peer's, so the lookup finds nothing and containment stays on the IP.

use std::net::IpAddr;

use guardian_core::machine::Mac;

/// The observed MAC of `ip`, if the neighbour table has a complete entry.
/// Blocking (a file read on Linux, a short command elsewhere): call it from
/// `spawn_blocking`.
pub fn lookup(ip: IpAddr) -> Option<Mac> {
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    let table = table(ip)?;
    parse(&table, ip)
}

#[cfg(target_os = "linux")]
fn table(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(_) => std::fs::read_to_string("/proc/net/arp").ok(),
        // `ip` is an address type, passed as its own argument: no shell.
        IpAddr::V6(_) => command("ip", &["-6", "neigh", "show", &ip.to_string()]),
    }
}

#[cfg(windows)]
fn table(ip: IpAddr) -> Option<String> {
    command("arp", &["-a", &ip.to_string()])
}

#[cfg(not(any(target_os = "linux", windows)))]
fn table(ip: IpAddr) -> Option<String> {
    command("arp", &["-n", &ip.to_string()])
}

fn command(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Finds the MAC on the line of `ip` in any of the tables above:
/// `/proc/net/arp`, `ip neigh`, Windows `arp -a` and BSD `arp -n`. Incomplete
/// entries (all zeros) and multicast addresses are not hosts.
pub fn parse(table: &str, ip: IpAddr) -> Option<Mac> {
    let wanted = ip.to_string();
    table.lines().find_map(|line| {
        let mut tokens = line
            .split_whitespace()
            .map(|t| t.trim_matches(|c| c == '(' || c == ')'));
        if !tokens.clone().any(|t| t == wanted) {
            return None;
        }
        tokens.find_map(Mac::parse).filter(Mac::is_unicast)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn reads_the_linux_arp_table() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device\n\
                     192.168.88.20    0x1         0x2         52:54:00:12:34:56     *        eth0\n\
                     192.168.88.21    0x1         0x0         00:00:00:00:00:00     *        eth0\n\
                     192.168.88.2     0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n";
        assert_eq!(
            parse(table, ip("192.168.88.20")),
            Mac::parse("52:54:00:12:34:56")
        );
        // An incomplete entry is no MAC.
        assert_eq!(parse(table, ip("192.168.88.21")), None);
        // A prefix of another address does not match.
        assert_eq!(parse(table, ip("192.168.88.200")), None);
        assert_eq!(
            parse(table, ip("192.168.88.2")),
            Mac::parse("aa:bb:cc:dd:ee:01")
        );
    }

    #[test]
    fn reads_windows_and_bsd_arp_and_ip_neigh() {
        let windows = "\nInterface: 192.168.88.10 --- 0x7\n  Internet Address      Physical Address      Type\n  192.168.88.20         52-54-00-12-34-56     dynamic\n  224.0.0.251           01-00-5e-00-00-fb     static\n";
        assert_eq!(
            parse(windows, ip("192.168.88.20")),
            Mac::parse("52:54:00:12:34:56")
        );
        assert_eq!(parse(windows, ip("224.0.0.251")), None);
        // The interface line holds our own address, never a MAC.
        assert_eq!(parse(windows, ip("192.168.88.10")), None);

        let bsd = "? (192.168.88.20) at 52:54:0:12:34:56 on en0 ifscope [ethernet]\n\
                   ? (192.168.88.21) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n";
        assert_eq!(
            parse(bsd, ip("192.168.88.21")),
            Mac::parse("aa:bb:cc:dd:ee:ff")
        );

        let neigh = "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:02 REACHABLE\n";
        assert_eq!(parse(neigh, ip("fe80::1")), Mac::parse("aa:bb:cc:dd:ee:02"));
    }

    #[test]
    fn loopback_has_no_mac() {
        assert_eq!(lookup(ip("127.0.0.1")), None);
        assert_eq!(lookup(ip("::1")), None);
    }
}
