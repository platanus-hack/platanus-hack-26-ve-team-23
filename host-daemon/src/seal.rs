//! The daemon's key sealed by this machine's TPM (ADR-0021). On Windows,
//! through the Platform Crypto Provider, the way Nepheral seals its node
//! store: an RSA key made inside the TPM, which never leaves it, wraps a
//! random data key, and the data key encrypts `host.key` with
//! XChaCha20-Poly1305. A copy of the file opens on no other machine, and on
//! this one only for the same Windows user.
//!
//! Elsewhere (Linux, macOS) there is no sealing yet: `available()` is false
//! and the key stays as before. `HAWK_TPM=0` turns sealing off.
//!
//! The only `unsafe` in the daemon is the NCrypt FFI below, Windows only.

/// `HTPM1`, the OAEP hash (1 SHA-1, 2 SHA-256), the wrapped key's length
/// (u16, big-endian), the key wrapped by the TPM, a 24-byte nonce, and the
/// data under XChaCha20-Poly1305 with that key.
const MAGIC: &[u8; 5] = b"HTPM1";
const NONCE_LEN: usize = 24;

pub fn is_sealed(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

/// Whether new keys are sealed: a TPM 2.0 answers and `HAWK_TPM` is not `0`.
pub fn available() -> bool {
    enabled(std::env::var("HAWK_TPM").ok().as_deref()) && imp::detect().is_some()
}

fn enabled(switch: Option<&str>) -> bool {
    switch.map(str::trim) != Some("0")
}

pub fn seal(plain: &[u8]) -> Result<Vec<u8>, String> {
    imp::seal(plain)
}

pub fn unseal(sealed: &[u8]) -> Result<Vec<u8>, String> {
    imp::unseal(sealed)
}

/// A sealed file split into its parts.
struct Parts<'a> {
    hash: u8,
    wrapped: &'a [u8],
    nonce: &'a [u8],
    ct: &'a [u8],
}

/// Splits a sealed file, refusing a truncated one before the TPM is asked.
fn parse(sealed: &[u8]) -> Result<Parts<'_>, String> {
    let body = sealed
        .strip_prefix(MAGIC.as_slice())
        .ok_or("TPM: not a sealed key")?;
    let (&hash, rest) = body.split_first().ok_or("TPM: truncated")?;
    if rest.len() < 2 {
        return Err("TPM: truncated".into());
    }
    let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    let rest = &rest[2..];
    if rest.len() < n + NONCE_LEN {
        return Err("TPM: truncated".into());
    }
    let (wrapped, rest) = rest.split_at(n);
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    Ok(Parts {
        hash,
        wrapped,
        nonce,
        ct,
    })
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod imp {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use rand::RngCore;
    use windows_sys::core::{HRESULT, PCWSTR};
    use windows_sys::Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptDecrypt, NCryptEncrypt, NCryptFinalizeKey,
        NCryptFreeObject, NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider,
        NCryptSetProperty, BCRYPT_OAEP_PADDING_INFO, BCRYPT_SHA1_ALGORITHM,
        BCRYPT_SHA256_ALGORITHM, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_KEY_HANDLE,
        NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG, NCRYPT_PCP_PLATFORM_TYPE_PROPERTY,
        NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM, NCRYPT_SILENT_FLAG,
    };
    use zeroize::Zeroizing;

    use super::{parse, MAGIC, NONCE_LEN};
    use crate::tpm::{kind_of, Kind};

    const KEY_NAME: PCWSTR = windows_sys::core::w!("HAWK host daemon");

    /// An NCrypt handle, freed on drop.
    #[derive(Debug)]
    struct Handle(usize);

    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: a handle NCrypt gave out and nothing else frees.
                unsafe { NCryptFreeObject(self.0) };
            }
        }
    }

    fn check(hr: HRESULT, what: &str) -> Result<(), String> {
        if hr == 0 {
            Ok(())
        } else {
            Err(format!("TPM: {what} failed (0x{:08x})", hr as u32))
        }
    }

    fn provider() -> Result<Handle, String> {
        let mut prov: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: an out-pointer to a local.
        check(
            unsafe { NCryptOpenStorageProvider(&mut prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) },
            "opening the platform provider",
        )?;
        Ok(Handle(prov))
    }

    /// The TPM 2.0 there is, if any.
    pub fn detect() -> Option<Kind> {
        let prov = provider().ok()?;
        let mut buf = [0u8; 512];
        let mut len = 0u32;
        // SAFETY: the buffer and its length are passed together.
        let hr = unsafe {
            NCryptGetProperty(
                prov.0,
                NCRYPT_PCP_PLATFORM_TYPE_PROPERTY,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut len,
                0,
            )
        };
        if hr != 0 {
            return None;
        }
        let wide: Vec<u16> = buf[..(len as usize).min(buf.len())]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&c| c != 0)
            .collect();
        kind_of(&String::from_utf16_lossy(&wide))
    }

    /// The wrapping key, made in the TPM the first time.
    fn key(create: bool) -> Result<(Handle, Handle), String> {
        let prov = provider()?;
        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: out-pointer to a local; the name is a static wide string.
        let hr = unsafe { NCryptOpenKey(prov.0, &mut key, KEY_NAME, 0, NCRYPT_SILENT_FLAG) };
        if hr == 0 {
            return Ok((prov, Handle(key)));
        }
        if !create {
            return Err(format!(
                "TPM: the wrapping key is gone (0x{:08x})",
                hr as u32
            ));
        }
        // SAFETY: as above.
        check(
            unsafe {
                NCryptCreatePersistedKey(prov.0, &mut key, NCRYPT_RSA_ALGORITHM, KEY_NAME, 0, 0)
            },
            "creating the wrapping key",
        )?;
        let key = Handle(key);
        let bits: u32 = 2048;
        // SAFETY: four bytes, as the length property expects.
        check(
            unsafe {
                NCryptSetProperty(
                    key.0,
                    NCRYPT_LENGTH_PROPERTY,
                    (&bits as *const u32).cast(),
                    4,
                    0,
                )
            },
            "sizing the wrapping key",
        )?;
        // SAFETY: a key made just above.
        check(
            unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) },
            "finishing the wrapping key",
        )?;
        Ok((prov, key))
    }

    fn oaep(hash: u8) -> BCRYPT_OAEP_PADDING_INFO {
        BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: if hash == 2 {
                BCRYPT_SHA256_ALGORITHM
            } else {
                BCRYPT_SHA1_ALGORITHM
            },
            pbLabel: std::ptr::null_mut(),
            cbLabel: 0,
        }
    }

    fn rsa(key: &Handle, input: &[u8], hash: u8, decrypt: bool) -> Result<Vec<u8>, String> {
        let pad = oaep(hash);
        let pad_ptr: *const core::ffi::c_void = (&pad as *const BCRYPT_OAEP_PADDING_INFO).cast();
        let call = |out: *mut u8, cap: u32, len: &mut u32| -> HRESULT {
            // SAFETY: input and output buffers are passed with their lengths;
            // the padding info outlives the call.
            unsafe {
                if decrypt {
                    NCryptDecrypt(
                        key.0,
                        input.as_ptr(),
                        input.len() as u32,
                        pad_ptr,
                        out,
                        cap,
                        len,
                        NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
                    )
                } else {
                    NCryptEncrypt(
                        key.0,
                        input.as_ptr(),
                        input.len() as u32,
                        pad_ptr,
                        out,
                        cap,
                        len,
                        NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
                    )
                }
            }
        };
        let mut len = 0u32;
        check(call(std::ptr::null_mut(), 0, &mut len), "sizing")?;
        let mut out = vec![0u8; len as usize];
        check(
            call(out.as_mut_ptr(), len, &mut len),
            if decrypt { "unsealing" } else { "sealing" },
        )?;
        out.truncate(len as usize);
        Ok(out)
    }

    pub fn seal(plain: &[u8]) -> Result<Vec<u8>, String> {
        let (_prov, key) = key(true)?;
        let mut dek = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut dek[..]);
        // SHA-256 where the TPM takes it, SHA-1 otherwise; both are sound
        // for wrapping a key.
        let (hash, wrapped) = match rsa(&key, &dek[..], 2, false) {
            Ok(w) => (2u8, w),
            Err(_) => (1u8, rsa(&key, &dek[..], 1, false)?),
        };
        let wrapped_len =
            u16::try_from(wrapped.len()).map_err(|_| "TPM: wrapped key too long".to_string())?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = XChaCha20Poly1305::new((&*dek).into())
            .encrypt(XNonce::from_slice(&nonce), plain)
            .map_err(|_| "TPM: encrypting failed".to_string())?;
        let mut out = Vec::with_capacity(MAGIC.len() + 3 + wrapped.len() + NONCE_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.push(hash);
        out.extend_from_slice(&wrapped_len.to_be_bytes());
        out.extend_from_slice(&wrapped);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn unseal(sealed: &[u8]) -> Result<Vec<u8>, String> {
        let parts = parse(sealed)?;
        let (_prov, key) = key(false)?;
        let dek = Zeroizing::new(rsa(&key, parts.wrapped, parts.hash, true)?);
        if dek.len() != 32 {
            return Err("TPM: wrong key size".into());
        }
        XChaCha20Poly1305::new(dek.as_slice().into())
            .decrypt(XNonce::from_slice(parts.nonce), parts.ct)
            .map_err(|_| "TPM: the key does not open with this machine's TPM".to_string())
    }
}

#[cfg(not(windows))]
mod imp {
    use crate::tpm::Kind;

    pub fn detect() -> Option<Kind> {
        None
    }

    pub fn seal(_plain: &[u8]) -> Result<Vec<u8>, String> {
        Err("TPM: sealing is only built for Windows".into())
    }

    pub fn unseal(sealed: &[u8]) -> Result<Vec<u8>, String> {
        super::parse(sealed)?;
        Err("TPM: this key was sealed on Windows and only opens there".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_truncated_key_is_refused_before_the_tpm_is_asked() {
        assert!(unseal(b"HTPM1").is_err());
        assert!(unseal(b"HTPM1\x02\x01\x00abc").is_err());
        assert!(parse(b"HTPM1\x02\x00\x02ab012345678901234567890123ct").is_ok());
    }

    #[test]
    fn a_plain_hex_key_is_not_taken_for_a_sealed_one() {
        assert!(!is_sealed(b"00112233445566778899aabbccddeeff"));
        assert!(is_sealed(b"HTPM1\x02\x00\x00"));
    }

    #[test]
    fn hawk_tpm_0_turns_sealing_off() {
        assert!(!enabled(Some("0")));
        assert!(!enabled(Some(" 0 ")));
        assert!(enabled(Some("1")));
        assert!(enabled(None));
    }

    /// Uses this computer's TPM: `cargo test -p host-daemon seal -- --ignored`.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn the_real_tpm_seals_and_opens() {
        if imp::detect().is_none() {
            eprintln!("no TPM 2.0 here");
            return;
        }
        let plain = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let sealed = seal(plain).unwrap();
        assert!(is_sealed(&sealed));
        assert_eq!(unseal(&sealed).unwrap(), plain);
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(unseal(&bad).is_err());
    }
}
