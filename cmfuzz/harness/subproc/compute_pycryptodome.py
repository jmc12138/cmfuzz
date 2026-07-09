#!/usr/bin/env python3
"""CMFuzz stage 3 — PyCryptodome cross-language compute backend.

Implements the same wire protocol as the C/Go/Rust subprocess backends
(harness/subproc/compute_common.h): read "<op> <hex>" lines from stdin, where
hex = key(32) || nonce(12) || aadlen(2, BE) || aad || msg, and print the hex
result (or "NA" / "ERR") per line.

PyCryptodome is a genuinely independent implementation (its own C/asm core, not
an OpenSSL wrapper — unlike pyca/cryptography), so byte-exact agreement with the
OpenSSL reference is a real cross-language O1 differential. X25519 is not
provided by PyCryptodome, so op 12 replies NA (skipped by the runner).

CMF_PY_FAULT=1 in the environment flips the first output byte on every reply so
the negative self-test can prove the differential catches a divergent backend.
"""
import os
import sys

from Crypto.Hash import (SHA256, SHA512, SHA3_256, SHA3_512, SHAKE128, SHAKE256,
                         HMAC)
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, eddsa, pss

KEYLEN, NONCELEN = 32, 12
FAULT = os.environ.get("CMF_PY_FAULT") == "1"


def parse(blob):
    """Return (key, nonce, aad, msg) mirroring cmf_vec_parse."""
    need = KEYLEN + NONCELEN + 2
    if len(blob) < need:
        return b"", b"", b"", blob  # short blob: all message
    key = blob[:KEYLEN]
    nonce = blob[KEYLEN:KEYLEN + NONCELEN]
    p = blob[KEYLEN + NONCELEN:]
    aadlen = (p[0] << 8) | p[1]
    rest = p[2:]
    if aadlen > len(rest):
        aadlen = len(rest)
    return key, nonce, rest[:aadlen], rest[aadlen:]


def parse_verify(payload):
    """pubkeylen(2,BE)||pub||siglen(2,BE)||sig||msg."""
    if len(payload) < 2:
        raise ValueError("short")
    pl = (payload[0] << 8) | payload[1]
    off = 2
    pub = payload[off:off + pl]; off += pl
    sl = (payload[off] << 8) | payload[off + 1]; off += 2
    sig = payload[off:off + sl]; off += sl
    msg = payload[off:]
    return pub, sig, msg


def compute(op, blob):
    key, nonce, aad, msg = parse(blob)
    if op == 0:
        return SHA256.new(msg).digest()
    if op == 1:
        return SHA512.new(msg).digest()
    if op == 2:
        return HMAC.new(key, msg, digestmod=SHA256).digest()
    if op == 3:
        c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        if aad:
            c.update(aad)
        ct, tag = c.encrypt_and_digest(msg)
        return ct + tag
    if op == 4:
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            c.update(aad)
        ct, tag = c.encrypt_and_digest(msg)
        return ct + tag
    if op == 5:
        return SHA3_256.new(msg).digest()
    if op == 6:
        return SHA3_512.new(msg).digest()
    if op == 7:
        return SHAKE128.new(msg).read(32)
    if op == 8:
        return SHAKE256.new(msg).read(64)
    if op == 9:
        return HKDF(msg, 42, key, SHA256, context=aad)
    if op == 10:
        return PBKDF2(msg, key, dkLen=32, count=4096, hmac_hash_module=SHA256)
    if op == 11:
        k = ECC.construct(curve="Ed25519", seed=key)
        return eddsa.new(k, "rfc8032").sign(msg)
    if op == 12:
        return None  # X25519 not supported by PyCryptodome -> NA
    if op == 13:
        pub, sig, m = parse_verify(msg)
        try:
            k = _sec1_to_key(pub)
            DSS.new(k, "fips-186-3", encoding="der").verify(SHA256.new(m), sig)
            return b"\x01"
        except Exception:
            return b"\x00"
    if op == 14:
        pub, sig, m = parse_verify(msg)
        try:
            n = int.from_bytes(pub, "big")
            k = RSA.construct((n, 65537))
            pss.new(k).verify(SHA256.new(m), sig)
            return b"\x01"
        except Exception:
            return b"\x00"
    return None


def _sec1_to_key(pub):
    """Build a P-256 ECC public key from a SEC1 uncompressed point (0x04||X||Y)."""
    if len(pub) != 65 or pub[0] != 0x04:
        raise ValueError("bad point")
    x = int.from_bytes(pub[1:33], "big")
    y = int.from_bytes(pub[33:65], "big")
    return ECC.construct(curve="P-256", point_x=x, point_y=y)


def main():
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            sp = line.index(" ")
            op = int(line[:sp])
            blob = bytes.fromhex(line[sp + 1:])
        except ValueError:
            out.write("ERR\n"); out.flush(); continue
        try:
            res = compute(op, blob)
        except Exception:
            res = b"__ERR__"
        if res is None:
            out.write("NA\n")
        elif res == b"__ERR__":
            out.write("ERR\n")
        else:
            b = bytearray(res)
            if FAULT and b:
                b[0] ^= 0xFF
            out.write(b.hex() + "\n")
        out.flush()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # the runner closes the pipe as soon as it sees a mismatch; exit quietly
        try:
            sys.stdout.close()
        except Exception:
            pass
        os._exit(0)
