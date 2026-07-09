// CMFuzz stage 2.4 — RustCrypto cross-language differential backend.
//
// A drop-in backend for the subprocess differential runner (diff_subproc): it
// speaks the exact same wire protocol as the C compute CLIs (compute_common.h)
// and the Go backend — one "<op> <hex-blob>" request per stdin line, one hex
// (or "01"/"00" verdict, or "NA"/"ERR") response per stdout line — but computes
// every primitive with the RustCrypto crates + dalek instead of a C library.
// Because that stack is an independent implementation lineage (not derived from
// OpenSSL/BoringSSL), byte-for-byte agreement against the OpenSSL reference is a
// genuine cross-language O1 differential.
//
// Building with `--features fault` (see build_rust_diff.sh) corrupts the first
// output so the negative self-test can prove the differential catches a
// divergence.

use std::io::{self, BufRead, BufReader, BufWriter, Write};

const KEYLEN: usize = 32;
const NONCELEN: usize = 12;
const RSA_PUB_E: u32 = 65537;
const HKDF_OUT: usize = 42;
const PBKDF2_DK: usize = 32;
const PBKDF2_IT: u32 = 4096;

#[cfg(feature = "fault")]
const FAULT: bool = true;
#[cfg(not(feature = "fault"))]
const FAULT: bool = false;

struct Vec_<'a> {
    key: &'a [u8],
    msg: &'a [u8],
    aad: &'a [u8],
}

// parse_vec mirrors cmf_vec_parse: key(32) || nonce(12) || aadlen(2 BE) || aad || msg.
fn parse_vec(blob: &[u8]) -> Vec_<'_> {
    let need = KEYLEN + NONCELEN + 2;
    if blob.len() < need {
        return Vec_ { key: &[], msg: blob, aad: &[] };
    }
    let key = &blob[..KEYLEN];
    let p = &blob[KEYLEN + NONCELEN..];
    let aadlen = ((p[0] as usize) << 8) | p[1] as usize;
    let rest = &blob[need..];
    let aadlen = aadlen.min(rest.len());
    Vec_ { key, aad: &rest[..aadlen], msg: &rest[aadlen..] }
}

// parse_verify_payload mirrors cmf_verify_parse: publen(2) || pub || siglen(2) || sig || msg.
fn parse_verify_payload(p: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    if p.len() < 2 {
        return None;
    }
    let pl = ((p[0] as usize) << 8) | p[1] as usize;
    let mut off = 2;
    if off + pl + 2 > p.len() {
        return None;
    }
    let pubk = &p[off..off + pl];
    off += pl;
    let sl = ((p[off] as usize) << 8) | p[off + 1] as usize;
    off += 2;
    if off + sl > p.len() {
        return None;
    }
    let sig = &p[off..off + sl];
    off += sl;
    let msg = &p[off..];
    Some((pubk, sig, msg))
}

fn sha256(msg: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(msg))
}

fn sha512(msg: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    hex::encode(Sha512::digest(msg))
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).unwrap();
    m.update(msg);
    hex::encode(m.finalize().into_bytes())
}

fn sha3_256(msg: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    hex::encode(Sha3_256::digest(msg))
}

fn sha3_512(msg: &[u8]) -> String {
    use sha3::{Digest, Sha3_512};
    hex::encode(Sha3_512::digest(msg))
}

fn shake128_32(msg: &[u8]) -> String {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake128::default();
    h.update(msg);
    let mut r = h.finalize_xof();
    let mut out = [0u8; 32];
    r.read(&mut out);
    hex::encode(out)
}

fn shake256_64(msg: &[u8]) -> String {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    h.update(msg);
    let mut r = h.finalize_xof();
    let mut out = [0u8; 64];
    r.read(&mut out);
    hex::encode(out)
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> String {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; HKDF_OUT];
    if hk.expand(info, &mut okm).is_err() {
        return "ERR".into();
    }
    hex::encode(okm)
}

fn pbkdf2_sha256(pw: &[u8], salt: &[u8]) -> String {
    let mut out = [0u8; PBKDF2_DK];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw, salt, PBKDF2_IT, &mut out);
    hex::encode(out)
}

fn ed25519_sign(key: &[u8], msg: &[u8]) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    if key.len() < KEYLEN {
        return "ERR".into();
    }
    let seed: [u8; 32] = key[..KEYLEN].try_into().unwrap();
    let sk = SigningKey::from_bytes(&seed);
    hex::encode(sk.sign(msg).to_bytes())
}

fn x25519_op(key: &[u8], msg: &[u8]) -> String {
    if key.len() < KEYLEN || msg.len() < 32 {
        return "ERR".into();
    }
    let scalar: [u8; 32] = key[..32].try_into().unwrap();
    let peer: [u8; 32] = msg[..32].try_into().unwrap();
    hex::encode(x25519_dalek::x25519(scalar, peer))
}

fn ecdsa_p256_verify(payload: &[u8]) -> String {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let (pubk, sig, msg) = match parse_verify_payload(payload) {
        Some(t) => t,
        None => return "00".into(),
    };
    let vk = match VerifyingKey::from_sec1_bytes(pubk) {
        Ok(k) => k,
        Err(_) => return "00".into(),
    };
    let sig = match Signature::from_der(sig) {
        Ok(s) => s,
        Err(_) => return "00".into(),
    };
    if vk.verify(msg, &sig).is_ok() {
        "01".into()
    } else {
        "00".into()
    }
}

fn rsa_pss_verify(payload: &[u8]) -> String {
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::{BigUint, RsaPublicKey};
    let (pubk, sig, msg) = match parse_verify_payload(payload) {
        Some(t) => t,
        None => return "00".into(),
    };
    let n = BigUint::from_bytes_be(pubk);
    let e = BigUint::from(RSA_PUB_E);
    let key = match RsaPublicKey::new(n, e) {
        Ok(k) => k,
        Err(_) => return "00".into(),
    };
    let sig = match Signature::try_from(sig) {
        Ok(s) => s,
        Err(_) => return "00".into(),
    };
    let vk = VerifyingKey::<sha2::Sha256>::new(key);
    if vk.verify(msg, &sig).is_ok() {
        "01".into()
    } else {
        "00".into()
    }
}

fn aead_from_blob(op: i32, blob: &[u8]) -> String {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let need = KEYLEN + NONCELEN + 2;
    if blob.len() < need {
        return "ERR".into();
    }
    let key = &blob[..KEYLEN];
    let nonce = &blob[KEYLEN..KEYLEN + NONCELEN];
    let p = &blob[KEYLEN + NONCELEN..];
    let aadlen = (((p[0] as usize) << 8) | p[1] as usize).min(blob.len() - need);
    let rest = &blob[need..];
    let aad = &rest[..aadlen];
    let msg = &rest[aadlen..];
    let pl = Payload { msg, aad };
    let ct = if op == 3 {
        use chacha20poly1305::ChaCha20Poly1305;
        let c = match ChaCha20Poly1305::new_from_slice(key) {
            Ok(c) => c,
            Err(_) => return "ERR".into(),
        };
        c.encrypt(nonce.into(), pl)
    } else {
        use aes_gcm::Aes256Gcm;
        let c = match Aes256Gcm::new_from_slice(key) {
            Ok(c) => c,
            Err(_) => return "ERR".into(),
        };
        c.encrypt(nonce.into(), pl)
    };
    match ct {
        Ok(b) => hex::encode(b),
        Err(_) => "ERR".into(),
    }
}

// dispatch handles the AEAD nonce (which parse_vec drops) and computes every
// other op from the parsed vector. Returns "NA" for unimplemented ops.
fn dispatch(op: i32, blob: &[u8]) -> String {
    if op == 3 || op == 4 {
        return aead_from_blob(op, blob);
    }
    let v = parse_vec(blob);
    match op {
        0 => sha256(v.msg),
        1 => sha512(v.msg),
        2 => hmac_sha256(v.key, v.msg),
        5 => sha3_256(v.msg),
        6 => sha3_512(v.msg),
        7 => shake128_32(v.msg),
        8 => shake256_64(v.msg),
        9 => hkdf_sha256(v.msg, v.key, v.aad),
        10 => pbkdf2_sha256(v.msg, v.key),
        11 => ed25519_sign(v.key, v.msg),
        12 => x25519_op(v.key, v.msg),
        13 => ecdsa_p256_verify(v.msg),
        14 => rsa_pss_verify(v.msg),
        _ => "NA".into(),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    let mut line = String::new();
    let mut first = true;
    loop {
        line.clear();
        let n = reader.read_line(&mut line).unwrap_or(0);
        if n == 0 {
            break;
        }
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            continue;
        }
        let mut resp = match l.split_once(' ') {
            Some((ops, hexs)) => match (ops.trim().parse::<i32>(), hex::decode(hexs.trim())) {
                (Ok(op), Ok(blob)) => dispatch(op, &blob),
                _ => "ERR".into(),
            },
            None => "ERR".into(),
        };
        if FAULT && first && resp != "NA" {
            resp = "ff".into();
        }
        first = false;
        let _ = writer.write_all(resp.as_bytes());
        let _ = writer.write_all(b"\n");
    }
    let _ = writer.flush();
}
