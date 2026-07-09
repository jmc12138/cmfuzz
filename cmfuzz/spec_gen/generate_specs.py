#!/usr/bin/env python3
"""Generate per-algorithm specs (Pillar 1).

Enumerates the algorithms exposed by a target library and emits one JSON spec per
algorithm into ``specs/<kind>/<name>.json``. For each algorithm it first tries the
LLM backend (``llm_client``) to extract constraints/oracles from the header; if no
API key is configured it falls back to offline, kind-specific oracle templates.

Usage:
    python3 spec_gen/generate_specs.py --liboqs libs/liboqs [--llm]
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from llm_client import LLMClient  # noqa: E402


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def offline_kem_spec(name: str, lib: str) -> dict:
    return {
        "name": name, "library": lib, "kind": "kem", "lib_alg_id": name,
        "security_notion": "IND-CCA2",
        "function_signature": {
            "keypair": "OQS_STATUS keypair(uint8_t *pk, uint8_t *sk)",
            "encaps": "OQS_STATUS encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)",
            "decaps": "OQS_STATUS decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)",
        },
        "input_constraints": {
            "ciphertext": {"len": "length_ciphertext",
                           "note": "fixed length; attacker-controlled in MEM mode"},
        },
        "oracles": [
            {"id": "MR1_correctness", "type": "metamorphic",
             "relation": "decaps(sk, encaps(pk).ct) == encaps(pk).ss"},
            {"id": "MR2_malleability", "type": "security", "notion": "IND-CCA2",
             "relation": "decaps(sk, mutate(ct)) != ss"},
            {"id": "MR3_wrong_key", "type": "security",
             "relation": "decaps(sk', ct) != ss for sk' != sk"},
            {"id": "MR4_determinism", "type": "metamorphic",
             "relation": "decaps(sk, ct) stable"},
            {"id": "MEM", "type": "memory",
             "relation": "decaps(sk, arbitrary_bytes) memory-safe"},
        ],
        "constant_time": {"target": "decaps", "secret_input": "sk", "public_input": "ct"},
        "source": "offline_template",
    }


def offline_sig_spec(name: str, lib: str) -> dict:
    return {
        "name": name, "library": lib, "kind": "sig", "lib_alg_id": name,
        "security_notion": "EUF-CMA",
        "function_signature": {
            "keypair": "OQS_STATUS keypair(uint8_t *pk, uint8_t *sk)",
            "sign": "OQS_STATUS sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk)",
            "verify": "OQS_STATUS verify(const uint8_t *m, size_t mlen, const uint8_t *sig, size_t siglen, const uint8_t *pk)",
        },
        "oracles": [
            {"id": "MR1_correctness", "type": "metamorphic",
             "relation": "verify(pk, m, sign(sk, m)) == 1"},
            {"id": "MR2_message_binding", "type": "security", "notion": "EUF-CMA",
             "relation": "verify(pk, m', sig) == 0 for m' != m"},
            {"id": "MR3_strong_unforgeability", "type": "security", "notion": "SUF-CMA",
             "relation": "verify(pk, m, mutate(sig)) == 0"},
            {"id": "MR4_wrong_key", "type": "security",
             "relation": "verify(pk', m, sig) == 0 for pk' != pk"},
            {"id": "MEM", "type": "memory",
             "relation": "verify(pk, m, arbitrary_bytes) memory-safe"},
        ],
        "constant_time": {"target": "sign", "secret_input": "sk", "public_input": "m"},
        "source": "offline_template",
    }


def enum_liboqs(header_path: str, macro_prefix: str) -> list[str]:
    """Parse OQS_{KEM,SIG}_alg_* identifiers -> their string values."""
    algs = []
    txt = open(header_path, encoding="utf-8", errors="ignore").read()
    for m in re.finditer(r'#define\s+' + macro_prefix + r'\w+\s+"([^"]+)"', txt):
        algs.append(m.group(1))
    return sorted(set(algs))


def read_header(path: str) -> str:
    try:
        return open(path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--liboqs", default=os.path.join(ROOT, "libs", "liboqs"))
    ap.add_argument("--llm", action="store_true", help="use LLM backend if key present")
    args = ap.parse_args()

    llm = LLMClient() if args.llm else None
    if args.llm:
        print(f"[spec] LLM backend available: {llm.available} "
              f"(provider={llm.provider})")

    kem_h = os.path.join(args.liboqs, "src", "kem", "kem.h")
    sig_h = os.path.join(args.liboqs, "src", "sig", "sig.h")
    kem_algs = enum_liboqs(kem_h, "OQS_KEM_alg_")
    sig_algs = enum_liboqs(sig_h, "OQS_SIG_alg_")
    print(f"[spec] liboqs: {len(kem_algs)} KEMs, {len(sig_algs)} SIGs")

    count = 0
    for name in kem_algs:
        spec = None
        if llm and llm.available:
            spec = llm.extract_spec(name, "kem", "IND-CCA2", read_header(kem_h))
        if not spec:
            spec = offline_kem_spec(name, "liboqs")
        out = os.path.join(ROOT, "specs", "kem", name.replace("/", "_") + ".json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        json.dump(spec, open(out, "w"), indent=2)
        count += 1
    for name in sig_algs:
        spec = None
        if llm and llm.available:
            spec = llm.extract_spec(name, "sig", "EUF-CMA", read_header(sig_h))
        if not spec:
            spec = offline_sig_spec(name, "liboqs")
        out = os.path.join(ROOT, "specs", "sig", name.replace("/", "_") + ".json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        json.dump(spec, open(out, "w"), indent=2)
        count += 1

    print(f"[spec] wrote {count} specs into specs/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
