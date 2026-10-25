//! TPM 2.0 support for the host daemon (ADR-0021): what kind of TPM this
//! machine has, and a measurement of its boot state (the SHA-256 digest of
//! the first PCRs) that the daemon reports in its heartbeat.
//!
//! The demo reads the PCRs directly from the Linux TPM driver (a Hyper-V Gen2
//! virtual machine with a vTPM). On Windows, and in the software fallback, no
//! measurement is produced and the host runs without attestation. On Windows
//! the daemon key is sealed by the TPM (`seal.rs`); signing with a
//! TPM-resident key and Linux sealing (`tss-esapi`) are the next step.

use sha2::{Digest as _, Sha256};

/// What kind of TPM 2.0, as reported by the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// On Windows the platform string is not read yet (no unsafe FFI in this
// crate), so the kind is only exercised by tests; the enum stays for the
// documented Windows NCrypt path.
#[allow(dead_code)]
pub enum Kind {
    /// A discrete chip on the board.
    Discrete,
    /// Firmware TPM (Intel PTT, AMD fTPM, Qualcomm).
    Firmware,
    /// Microsoft Pluton.
    Pluton,
}

/// From the platform-provider description, e.g.
/// `TPM-Version:2.0 -Level:0-Revision:1.38-VendorID:'INTC'-Firmware:…`.
#[allow(dead_code)]
pub fn kind_of(platform: &str) -> Option<Kind> {
    if !platform.contains("TPM-Version:2.0") {
        return None;
    }
    let vendor = platform
        .split("VendorID:'")
        .nth(1)
        .and_then(|v| v.split('\'').next())
        .unwrap_or("")
        .trim()
        .to_ascii_uppercase();
    Some(match vendor.as_str() {
        "MSFT" => Kind::Pluton,
        "INTC" | "AMD" | "QCOM" | "HISI" => Kind::Firmware,
        _ => Kind::Discrete,
    })
}

/// The boot measurement: SHA-256 over the domain and the PCR values, so a
/// changed boot changes the digest. Pure, for tests and the Linux reader.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn digest_of_pcrs(values: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"guardian.boot.v1");
    for value in values {
        hasher.update(value);
    }
    hasher.finalize().into()
}

/// The boot measurement of this machine, if a TPM is present and readable.
/// Linux reads the first PCRs of the TPM driver; elsewhere there is none.
#[cfg(target_os = "linux")]
pub fn boot_digest() -> Option<[u8; 32]> {
    const PCRS: usize = 8;
    let mut values = Vec::with_capacity(PCRS);
    for index in 0..PCRS {
        let path = format!("/sys/class/tpm/tpm0/pcr-sha256/{index}");
        let hex_value = std::fs::read_to_string(path).ok()?;
        let bytes = hex::decode(hex_value.trim()).ok()?;
        let value: [u8; 32] = bytes.try_into().ok()?;
        values.push(value);
    }
    Some(digest_of_pcrs(&values))
}

#[cfg(not(target_os = "linux"))]
pub fn boot_digest() -> Option<[u8; 32]> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_strings_say_what_kind() {
        let s =
            |v: &str| format!("TPM-Version:2.0 -Level:0-Revision:1.38-VendorID:'{v}'-Firmware:1");
        assert_eq!(kind_of(&s("INTC")), Some(Kind::Firmware));
        assert_eq!(kind_of(&s("AMD ")), Some(Kind::Firmware));
        assert_eq!(kind_of(&s("MSFT")), Some(Kind::Pluton));
        assert_eq!(kind_of(&s("IFX ")), Some(Kind::Discrete));
        assert_eq!(kind_of("TPM-Version:1.2 -VendorID:'IFX '"), None);
    }

    #[test]
    fn the_boot_digest_depends_on_every_pcr() {
        let a = digest_of_pcrs(&[[0u8; 32], [1u8; 32]]);
        let b = digest_of_pcrs(&[[0u8; 32], [2u8; 32]]);
        assert_ne!(a, b);
        assert_eq!(a, digest_of_pcrs(&[[0u8; 32], [1u8; 32]]));
        // An empty measurement is not a valid attestation, but is stable.
        assert_ne!(a, digest_of_pcrs(&[]));
    }
}
