//! What this daemon reports about its machine (ADR-0028): the OS machine id
//! (hashed per Core before it leaves, `guardian_core::machine::hwid`) and the
//! network interfaces with their MACs.
//!
//! Read from files and system commands with fixed arguments, never through a
//! shell. Parsers are plain functions so every platform's format is tested
//! everywhere.

use guardian_core::machine::{Mac, Nic};

/// The OS machine id: `/etc/machine-id` (Linux), `MachineGuid` (Windows),
/// `IOPlatformUUID` (macOS).
pub fn machine_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        ["/etc/machine-id", "/var/lib/dbus/machine-id"]
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    }
    #[cfg(windows)]
    {
        let out = command(
            "reg",
            &[
                "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v",
                "MachineGuid",
            ],
        )?;
        parse_reg_machine_guid(&out)
    }
    #[cfg(target_os = "macos")]
    {
        parse_ioreg_uuid(&command(
            "ioreg",
            &["-rd1", "-c", "IOPlatformExpertDevice"],
        )?)
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        None
    }
}

/// This machine's network interfaces with a unicast MAC.
pub fn nics() -> Vec<Nic> {
    #[cfg(target_os = "linux")]
    {
        linux_nics()
    }
    #[cfg(windows)]
    {
        command("getmac", &["/v", "/fo", "csv", "/nh"])
            .map(|out| parse_getmac(&out))
            .unwrap_or_default()
    }
    #[cfg(target_os = "macos")]
    {
        command("ifconfig", &[])
            .map(|out| parse_ifconfig(&out))
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        Vec::new()
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn command(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Interfaces without a `device` link are virtual (bridges, veth, tap): a
/// bridge on a workstation is where VMs get their own MAC.
#[cfg(target_os = "linux")]
fn linux_nics() -> Vec<Nic> {
    let Ok(dir) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut nics: Vec<Nic> = dir
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let address = std::fs::read_to_string(path.join("address")).ok()?;
            let mac = Mac::parse(&address).filter(Mac::is_unicast)?;
            let mut nic = Nic::new(&name, mac);
            nic.is_virtual |= !path.join("device").exists();
            Some(nic)
        })
        .collect();
    nics.sort_by(|a, b| a.name.cmp(&b.name));
    nics
}

/// `reg query ... /v MachineGuid`: `    MachineGuid    REG_SZ    <guid>`.
#[cfg_attr(not(windows), allow(dead_code))] // used on Windows, tested everywhere
fn parse_reg_machine_guid(out: &str) -> Option<String> {
    out.lines()
        .find(|l| l.trim_start().starts_with("MachineGuid"))
        .and_then(|l| l.split_whitespace().last())
        .map(str::to_owned)
}

/// `ioreg -rd1 -c IOPlatformExpertDevice`: `"IOPlatformUUID" = "<uuid>"`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // used on macOS, tested everywhere
fn parse_ioreg_uuid(out: &str) -> Option<String> {
    let line = out.lines().find(|l| l.contains("\"IOPlatformUUID\""))?;
    let value = line.split('=').nth(1)?.trim().trim_matches('"');
    (!value.is_empty()).then(|| value.to_owned())
}

/// `getmac /v /fo csv /nh`: `"Connection","Adapter","AA-BB-..","Transport"`.
/// The adapter description also decides whether it is virtual (Hyper-V,
/// VirtualBox, VMware).
#[cfg_attr(not(windows), allow(dead_code))] // used on Windows, tested everywhere
fn parse_getmac(out: &str) -> Vec<Nic> {
    out.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.trim().trim_matches('"').split("\",\"").collect();
            let [name, adapter, address, ..] = fields.as_slice() else {
                return None;
            };
            let mac = Mac::parse(address).filter(Mac::is_unicast)?;
            let mut nic = Nic::new(name, mac);
            nic.is_virtual |= guardian_core::machine::is_virtual(adapter, &mac);
            Some(nic)
        })
        .collect()
}

/// `ifconfig`: an interface header line, then `\tether aa:bb:..`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // used on macOS, tested everywhere
fn parse_ifconfig(out: &str) -> Vec<Nic> {
    let mut nics = Vec::new();
    let mut current = String::new();
    for line in out.lines() {
        if !line.starts_with(char::is_whitespace) {
            current = line.split(':').next().unwrap_or_default().to_owned();
        } else if let Some(rest) = line.trim().strip_prefix("ether ") {
            if let Some(mac) = rest
                .split_whitespace()
                .next()
                .and_then(Mac::parse)
                .filter(Mac::is_unicast)
            {
                nics.push(Nic::new(&current, mac));
            }
        }
    }
    nics
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_windows_machine_guid() {
        let out = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    MachineGuid    REG_SZ    4c4c4544-0042-3510-8051-b4c04f4e3232\r\n\r\n";
        assert_eq!(
            parse_reg_machine_guid(out).as_deref(),
            Some("4c4c4544-0042-3510-8051-b4c04f4e3232")
        );
        assert_eq!(parse_reg_machine_guid("ERROR: not found"), None);
    }

    #[test]
    fn reads_the_macos_platform_uuid() {
        let out = "+-o J314sAP  <class IOPlatformExpertDevice>\n    {\n      \"IOPlatformUUID\" = \"0A1B2C3D-0000-1111-2222-333344445555\"\n    }\n";
        assert_eq!(
            parse_ioreg_uuid(out).as_deref(),
            Some("0A1B2C3D-0000-1111-2222-333344445555")
        );
        assert_eq!(parse_ioreg_uuid("nothing"), None);
    }

    #[test]
    fn reads_windows_adapters_and_flags_hypervisors() {
        let out = "\"Ethernet\",\"Intel(R) Ethernet Connection I219-V\",\"3C-22-FB-01-02-03\",\"\\Device\\Tcpip_{A}\"\r\n\
                   \"vEthernet (Default Switch)\",\"Hyper-V Virtual Ethernet Adapter\",\"00-15-5D-AA-BB-CC\",\"\\Device\\Tcpip_{B}\"\r\n\
                   \"Bluetooth\",\"Bluetooth Device (PAN)\",\"N/A\",\"Media disconnected\"\r\n";
        let nics = parse_getmac(out);
        assert_eq!(nics.len(), 2);
        assert_eq!(nics[0].name, "Ethernet");
        assert!(!nics[0].is_virtual);
        assert_eq!(nics[1].mac, Mac::parse("00:15:5d:aa:bb:cc").unwrap());
        assert!(nics[1].is_virtual);
    }

    #[test]
    fn a_renamed_hypervisor_adapter_is_still_flagged() {
        let out =
            "\"LAN 2\",\"VirtualBox Host-Only Ethernet Adapter\",\"10-20-30-40-50-60\",\"x\"\r\n";
        assert!(parse_getmac(out)[0].is_virtual);
    }

    #[test]
    fn reads_macos_interfaces() {
        let out = "lo0: flags=8049<UP,LOOPBACK> mtu 16384\n\tinet 127.0.0.1\nen0: flags=8863<UP> mtu 1500\n\tether 3c:22:fb:01:02:03\n\tinet 192.168.1.5\nbridge100: flags=8863<UP> mtu 1500\n\tether 52:54:00:aa:bb:cc\n";
        let nics = parse_ifconfig(out);
        assert_eq!(nics.len(), 2);
        assert_eq!(nics[0].name, "en0");
        assert!(!nics[0].is_virtual);
        assert!(nics[1].is_virtual);
    }

    #[test]
    fn this_machine_reports_something_sane() {
        // Whatever this host has, the readers must not panic and every MAC
        // must be unicast.
        for nic in nics() {
            assert!(nic.mac.is_unicast());
        }
        if let Some(id) = machine_id() {
            assert!(!id.trim().is_empty());
        }
    }
}
