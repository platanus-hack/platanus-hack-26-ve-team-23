//! Identifiers of a machine beyond its IP address (ADR-0028): hardware
//! addresses, the hashed machine id (HWID) and the network interfaces a host
//! daemon reports. No I/O: the daemon reads the values, the Core observes
//! the MAC of its peers.
//!
//! Trust differs per identifier: the MAC the Core observes may be a
//! containment target; the HWID and the interfaces a daemon declares only
//! link identities over time and drive warnings.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

pub const HWID_DOMAIN: &[u8] = b"hawk.hwid.v1";

/// An EUI-48 hardware address, shown as `aa:bb:cc:dd:ee:ff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// Parses `aa:bb:cc:dd:ee:ff` or `AA-BB-CC-DD-EE-FF`.
    pub fn parse(text: &str) -> Option<Self> {
        let mut out = [0u8; 6];
        let mut parts = text.trim().split([':', '-']);
        for byte in &mut out {
            let part = parts.next()?;
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            *byte = u8::from_str_radix(part, 16).ok()?;
        }
        parts.next().is_none().then_some(Self(out))
    }

    /// A single host's address: not all zeros, not multicast or broadcast.
    pub fn is_unicast(&self) -> bool {
        self.0 != [0; 6] && self.0[0] & 1 == 0
    }

    /// Upper case with colons, as RouterOS prints it.
    pub fn upper(&self) -> String {
        self.to_string().to_uppercase()
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl Serialize for Mac {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Mac {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| serde::de::Error::custom("bad MAC address"))
    }
}

/// The HWID of a machine as one Core knows it:
/// `SHA-256(HWID_DOMAIN || core identity || machine id)`, first 16 bytes, hex.
///
/// - Only from the OS machine id (122 to 128 random bits), never from low
///   entropy values such as a MAC, an address or a hostname, so the hash
///   cannot be reversed by enumeration.
/// - Keyed by the Core's identity, so the same machine has a different HWID
///   for every Core and a value seen by one deployment is useless to another.
/// - Never an identity on its own: the Core binds it to the daemon identity
///   that first presented it (ADR-0028).
///
/// Empty when the machine id is unknown or too short to be a real one.
pub fn hwid(core: &[u8; 32], machine_id: &str) -> String {
    let id: String = machine_id
        .trim()
        .to_lowercase()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect();
    if id.len() < MIN_MACHINE_ID_HEX {
        return String::new();
    }
    let digest = Sha256::new()
        .chain_update(HWID_DOMAIN)
        .chain_update(core)
        .chain_update(id.as_bytes())
        .finalize();
    hex::encode(&digest[..16])
}

/// Hex digits a machine id must have: 32 for systemd and a Windows GUID.
pub const MIN_MACHINE_ID_HEX: usize = 32;

/// Whether a value from the wire is a well-formed HWID: 32 lower-case hex
/// digits. Anything else is dropped, not stored.
pub fn is_hwid(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A network interface as a daemon reports it. Declared, so a label and a
/// warning, never a containment target (ADR-0028).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nic {
    pub name: String,
    pub mac: Mac,
    /// A hypervisor or container adapter: the host is a VM or runs them.
    #[serde(default, rename = "virtual")]
    pub is_virtual: bool,
}

impl Nic {
    pub fn new(name: &str, mac: Mac) -> Self {
        let name: String = name.trim().chars().take(64).collect();
        Self {
            is_virtual: is_virtual(&name, &mac),
            name,
            mac,
        }
    }
}

/// Organisationally unique identifiers of hypervisors. Docker's `02:42`
/// prefix is checked on two bytes in `is_virtual`.
const VIRTUAL_OUIS: [[u8; 3]; 10] = [
    [0x00, 0x15, 0x5d], // Hyper-V
    [0x08, 0x00, 0x27], // VirtualBox
    [0x0a, 0x00, 0x27], // VirtualBox host-only
    [0x00, 0x05, 0x69], // VMware
    [0x00, 0x0c, 0x29], // VMware
    [0x00, 0x1c, 0x14], // VMware
    [0x00, 0x50, 0x56], // VMware
    [0x52, 0x54, 0x00], // QEMU / KVM
    [0x00, 0x16, 0x3e], // Xen
    [0x00, 0x1c, 0x42], // Parallels
];

/// How the names of hypervisor and container adapters start, lower case.
const VIRTUAL_PREFIXES: [&str; 11] = [
    "vethernet",
    "vboxnet",
    "vmnet",
    "virbr",
    "vnet",
    "docker",
    "veth",
    "br-",
    "lxc",
    "lxd",
    "podman",
];

/// Words in the description of a hypervisor adapter, lower case.
const VIRTUAL_WORDS: [&str; 3] = ["hyper-v", "virtualbox", "vmware"];

/// Whether an adapter belongs to a hypervisor or a container runtime, by its
/// MAC prefix or its name.
pub fn is_virtual(name: &str, mac: &Mac) -> bool {
    let oui = [mac.0[0], mac.0[1], mac.0[2]];
    let docker = mac.0[0] == 0x02 && mac.0[1] == 0x42;
    let name = name.to_lowercase();
    docker
        || VIRTUAL_OUIS.contains(&oui)
        || VIRTUAL_PREFIXES.iter().any(|p| name.starts_with(p))
        || VIRTUAL_WORDS.iter().any(|w| name.contains(w))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_parse_in_both_notations_and_print_lower_case() {
        let mac = Mac::parse("AA-BB-CC-0D-0E-0F").unwrap();
        assert_eq!(mac, Mac::parse("aa:bb:cc:0d:0e:0f").unwrap());
        assert_eq!(mac.to_string(), "aa:bb:cc:0d:0e:0f");
        assert_eq!(mac.upper(), "AA:BB:CC:0D:0E:0F");
    }

    #[test]
    fn malformed_macs_are_refused() {
        for bad in [
            "",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "+a:bb:cc:dd:ee:ff",
            "aaa:bb:cc:dd:ee:f",
            "zz:bb:cc:dd:ee:ff",
        ] {
            assert!(Mac::parse(bad).is_none(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn only_unicast_macs_are_hosts() {
        assert!(Mac::parse("00:15:5d:01:02:03").unwrap().is_unicast());
        assert!(!Mac::parse("00:00:00:00:00:00").unwrap().is_unicast());
        assert!(!Mac::parse("ff:ff:ff:ff:ff:ff").unwrap().is_unicast());
        assert!(!Mac::parse("01:00:5e:00:00:fb").unwrap().is_unicast());
    }

    #[test]
    fn a_mac_round_trips_through_json() {
        let mac = Mac::parse("52:54:00:12:34:56").unwrap();
        let json = serde_json::to_string(&mac).unwrap();
        assert_eq!(json, r#""52:54:00:12:34:56""#);
        assert_eq!(serde_json::from_str::<Mac>(&json).unwrap(), mac);
        assert!(serde_json::from_str::<Mac>(r#""nope""#).is_err());
    }

    #[test]
    fn the_hwid_is_stable_keyed_by_core_and_domain_separated() {
        let core = [7u8; 32];
        let id = "4c4c4544-0042-3510-8051-b4c04f4e3232";
        let a = hwid(&core, id);
        assert!(is_hwid(&a));
        // Case, dashes and spaces do not change it.
        assert_eq!(
            a,
            hwid(
                &core,
                &format!(
                    "  {}
",
                    id.to_uppercase()
                )
            )
        );
        assert_eq!(a, hwid(&core, &id.replace('-', "")));
        assert!(!a.contains("4c4c4544"));
        assert_ne!(a, hwid(&core, "9f86d081884c7d659a2feaa0c55ad015"));
        // Another Core sees another value.
        assert_ne!(a, hwid(&[8u8; 32], id));
        // Not the bare hash of the id.
        let plain = Sha256::digest(id.as_bytes());
        assert_ne!(a, hex::encode(&plain[..16]));
    }

    #[test]
    fn short_or_missing_machine_ids_give_no_hwid() {
        let core = [7u8; 32];
        assert_eq!(hwid(&core, ""), "");
        assert_eq!(hwid(&core, "  "), "");
        // A MAC or a hostname is not a machine id.
        assert_eq!(hwid(&core, "aa:bb:cc:dd:ee:ff"), "");
        assert_eq!(hwid(&core, "rig-07"), "");
    }

    #[test]
    fn only_well_formed_hwids_are_accepted_from_the_wire() {
        assert!(is_hwid("0123456789abcdef0123456789abcdef"));
        assert!(!is_hwid("0123456789ABCDEF0123456789ABCDEF"));
        assert!(!is_hwid("0123456789abcdef"));
        assert!(!is_hwid("0123456789abcdef0123456789abcdeg"));
        assert!(!is_hwid("<script>alert(1)</script>aaaaaaa"));
    }

    #[test]
    fn hypervisor_adapters_are_flagged() {
        let mac = |t| Mac::parse(t).unwrap();
        assert!(Nic::new("Ethernet", mac("00:15:5d:aa:bb:cc")).is_virtual);
        assert!(Nic::new("eth0", mac("52:54:00:aa:bb:cc")).is_virtual);
        assert!(Nic::new("docker0", mac("02:42:ac:11:00:02")).is_virtual);
        assert!(Nic::new("vEthernet (Default Switch)", mac("10:20:30:40:50:60")).is_virtual);
        assert!(Nic::new("VirtualBox Host-Only Network", mac("10:20:30:40:50:60")).is_virtual);
        assert!(!Nic::new("Wi-Fi", mac("3c:22:fb:01:02:03")).is_virtual);
        assert!(!Nic::new("enp3s0", mac("3c:22:fb:01:02:03")).is_virtual);
    }
}
