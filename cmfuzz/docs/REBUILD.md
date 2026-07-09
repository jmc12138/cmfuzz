# Rebuilding the CMFuzz environment (fresh machine / new VM)

The repo only tracks source (harnesses, engine, specs, scripts, docs). The target
libraries (`liboqs`, `SEAL`, `libsodium`/`mbedtls`/`cryptopp`) and all build
artifacts live under `libs/` and `build/`, which are **gitignored** — so a fresh
checkout has no toolchain and no compiled harnesses. This doc is the fast path to
get back to a working, fuzzable state.

There are two ways: **Docker** (one command, reproducible) or **manual** (when you
want to iterate on the host directly, e.g. inside a Devin VM).

---

## Option A — Docker (recommended for a clean, repeatable env)

From the project dir (the one containing the `Dockerfile`):

```bash
docker build -t cmfuzz .                       # installs toolchain, builds liboqs + harnesses, runs neg-tests
docker run --rm cmfuzz bash tests/negative_tests.sh   # expect: "10 passed, 0 failed"
docker run --rm -it cmfuzz bash                # interactive shell for campaigns
```

The image build **fails loudly** if the oracles stop firing (it runs
`tests/negative_tests.sh` as the last step), so a green build == a working env.

The image intentionally does **not** build Microsoft SEAL (FHE, O-FHE harness) or
the differential libs (libsodium/mbedtls/cryptopp, O1 differential harness) to
keep it small/fast. Build them on demand inside the container:

```bash
bash scripts/build_seal.sh        # FHE harness (heavy C++ build)
bash scripts/build_diff_libs.sh   # differential libs, then:
bash scripts/build_diff_harness.sh
bash scripts/build_subproc.sh     # stage-2.1 BoringSSL + aws-lc subprocess differential + L3 harnesses (needs Go)
```

The image preinstalls Go 1.22 under `/usr/local/go`, so `build_subproc.sh` (which
clones + builds BoringSSL and aws-lc) works on demand inside the container.
aws-lc's cmake requires **Go >= 1.20**; BoringSSL is built first and aws-lc is
skipped gracefully if Go is missing/too old.

---

## Option B — Manual (Ubuntu 22.04, matches the Devin VM)

### 1. Toolchain

```bash
sudo apt-get update
sudo apt-get install -y clang cmake ninja-build libssl-dev git python3
# optional (only for the differential libs):
sudo apt-get install -y build-essential autoconf automake libtool pkg-config
# optional (only for the BoringSSL/aws-lc subprocess differential, stage 2.1):
# aws-lc needs Go >= 1.20; Ubuntu 22.04's apt golang-go is 1.18.1 (too old for
# aws-lc, fine for BoringSSL). Install an official Go toolchain for aws-lc:
curl -fsSL -o /tmp/go.tgz https://go.dev/dl/go1.22.5.linux-amd64.tar.gz \
  && sudo tar -C /usr/local -xzf /tmp/go.tgz    # -> /usr/local/go/bin/go
```

Versions known-good: **clang 14**, **cmake 3.22**, **ninja 1.10**, **OpenSSL/libssl-dev 3.0.2**.
`clang` ships libFuzzer + ASan/UBSan; no separate package needed.

### 2. Build liboqs (required for all PQC + composition-PQC harnesses)

```bash
bash scripts/build_liboqs.sh      # clones open-quantum-safe/liboqs, builds static Debug -> libs/liboqs/build/lib/liboqs.a
```

### 3. Build the harnesses

```bash
bash scripts/build_harness.sh     # liboqs KEM/SIG harnesses
# L1/L2/L3 composition + sequence harnesses (see build_all.sh for the exact list):
#   trad_metamorphic, comp_hpke_{x25519,mlkem}, comp_trad,
#   comp_authkem_{classic,pqc}, comp_kdfchain, seq_aead, classic_openssl
```

`scripts/build_all.sh` does everything (liboqs + specs + all harnesses + SEAL +
diff libs + BoringSSL subprocess stack) in one shot, but it builds SEAL under
`set -e`; if you don't want the heavy SEAL build, build the pieces individually or
use the Docker image. The BoringSSL step (`build_subproc.sh`) is optional and
skips gracefully if Go is missing.

### 4. Verify

```bash
bash tests/negative_tests.sh      # expect "10 passed, 0 failed" (11 with diff libs built)
```

This is the ground truth that the environment is correct: it compiles
fault-injected harnesses and asserts each metamorphic/composition/sequence oracle
**fires** on the injected fault.

### 5. Run campaigns

```bash
bash scripts/run_campaign.sh      # functional fuzzing (all harnesses)
bash scripts/run_ct.sh            # constant-time (dudect) checks
# or a single harness:
timeout 60 ./build/harness/comp_hpke_mlkem -max_total_time=60 -print_final_stats=1
```

---

## Gotchas

- **liboqs / SEAL / the diff libs / BoringSSL / aws-lc are not in git** — they are
  cloned by their build scripts (`build_liboqs.sh`, `build_seal.sh`,
  `build_diff_libs.sh` which pins libsodium 1.0.20 / mbedtls-3.6.2 / cryptopp
  8.9.0, `build_boringssl.sh`, and `build_aws_lc.sh`). First build needs network
  access.
- **BoringSSL/aws-lc need Go and link with `clang++`** — their static
  `libcrypto.a` contains C++ objects, so consumers (compute CLI + L3 harness)
  must be *linked* with `clang++` even though the sources are C.
  `build_subproc.sh` handles this. **aws-lc's cmake requires Go >= 1.20**; the
  build scripts prefer `/usr/local/go/bin` over the apt Go (1.18.1) when present.
  aws-lc is optional in `build_subproc.sh` (BoringSSL is built first, aws-lc
  skipped if its build fails).
- **Debug build of liboqs** is intentional: ASan/UBSan traces are useless without
  frame info. Don't switch it to Release "for speed".
- **Optional libs skip gracefully**: `build_all.sh` and `negative_tests.sh` detect
  missing diff libs / SEAL and skip those targets, so a minimal (liboqs-only) setup
  still builds and passes 10/10.
- **Env verified good** when `tests/negative_tests.sh` prints `10 passed, 0 failed`.
