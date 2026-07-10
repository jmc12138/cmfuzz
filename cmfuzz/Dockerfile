# CMFuzz build/run environment.
#
# Rebuilds the full toolchain used to compile and fuzz the CMFuzz harnesses so a
# fresh machine (or a new Devin VM) can be brought up with a single command
# instead of re-installing packages and re-cloning/-building liboqs by hand.
#
# Build context must be the project dir (the one containing this Dockerfile,
# harness/, engine/, scripts/, tests/).
#
#   Build:  docker build -t cmfuzz .
#   Shell:  docker run --rm -it cmfuzz bash
#   Tests:  docker run --rm cmfuzz bash tests/negative_tests.sh   # expect: all passed
#
# liboqs is cloned + built *inside* the image (it is gitignored and not shipped
# in the repo). The optional differential libs (libsodium/mbedtls/crypto++),
# Microsoft SEAL + OpenFHE (stage-2.5 FHE differential), and BoringSSL/aws-lc
# (stage-2.1 subprocess differential) are NOT built here to keep the image
# small/fast; run scripts/build_diff_libs.sh, scripts/build_seal.sh +
# scripts/build_openfhe.sh, or scripts/build_subproc.sh inside the container if
# you need the differential (O1), FHE, or BoringSSL/aws-lc harnesses. Go 1.22 is
# preinstalled under /usr/local/go so build_subproc.sh (which builds BoringSSL
# and aws-lc — the latter needs Go >= 1.20) works on demand. The FHE self-test
# in negative_tests.sh SKIPs unless SEAL + OpenFHE have been built.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=clang CXX=clang++

# Toolchain: clang (ships libFuzzer + ASan/UBSan), cmake+ninja (liboqs/SEAL),
# libssl-dev (OpenSSL libcrypto headers), git/python3 (clone + spec_gen).
# The remaining packages (autoconf/automake/libtool/pkg-config/build-essential)
# are only needed by the optional differential libs — cheap to include so the
# image can build them on demand.
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
        clang \
        cmake \
        ninja-build \
        libssl-dev \
        git \
        ca-certificates \
        python3 \
        python3-pip \
        build-essential \
        autoconf \
        automake \
        libtool \
        pkg-config \
        libgcrypt20-dev \
        nettle-dev \
        default-jdk \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Go >= 1.20 is required by aws-lc's cmake (BoringSSL also uses Go). Ubuntu
# 22.04's apt golang-go is 1.18.1 (too old), so install an official toolchain.
ARG GO_VERSION=1.22.5
RUN arch="$(dpkg --print-architecture)" \
    && curl -fsSL -o /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:${PATH}"

# Rust toolchain for the stage-2.4 RustCrypto cross-language differential
# backend (harness/rustbridge). Pinned to 1.83 so the MSRV dependency pins in
# Cargo.toml resolve; installed under /opt/rust so it is world-usable.
ARG RUST_VERSION=1.83.0
ENV RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/opt/rust/cargo
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y \
        --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}"
ENV PATH="/opt/rust/cargo/bin:${PATH}"

# PyCryptodome: independent Python crypto implementation for the stage-3
# cross-language differential (harness/subproc/compute_pycryptodome.py).
RUN pip3 install --no-cache-dir pycryptodome

WORKDIR /opt/cmfuzz
COPY . /opt/cmfuzz

# Build liboqs (static, Debug — ASan/UBSan get useful traces), the liboqs
# KEM/SIG harnesses, and the L1/L2/L3 composition + sequence harnesses used by
# the stage-1 campaigns. (build_all.sh also builds SEAL + the differential libs;
# those are intentionally skipped here — run their scripts on demand.)
ARG SAN="-fsanitize=address,undefined,fuzzer -fno-sanitize-recover=undefined -g -O1"
RUN bash scripts/build_liboqs.sh \
    && bash scripts/build_harness.sh \
    && mkdir -p build/harness \
    && OQS_INC="-Ilibs/liboqs/build/include" \
    && OQS_LIB="libs/liboqs/build/lib/liboqs.a" \
    && clang $SAN harness/openssl_classic_harness.c -lcrypto -o build/harness/classic_openssl \
    && clang $SAN harness/trad_metamorphic_harness.c -lcrypto -o build/harness/trad_metamorphic \
    && clang $SAN -DCMF_HPKE_KEM=0 harness/comp_hpke_harness.c -lcrypto -o build/harness/comp_hpke_x25519 \
    && clang $SAN -DCMF_HPKE_KEM=1 $OQS_INC harness/comp_hpke_harness.c $OQS_LIB -lcrypto -o build/harness/comp_hpke_mlkem \
    && clang $SAN harness/comp_trad_harness.c -lcrypto -o build/harness/comp_trad \
    && clang $SAN -DCMF_AK_PQC=0 harness/comp_authkem_harness.c -lcrypto -o build/harness/comp_authkem_classic \
    && clang $SAN -DCMF_AK_PQC=1 $OQS_INC harness/comp_authkem_harness.c $OQS_LIB -lcrypto -o build/harness/comp_authkem_pqc \
    && clang $SAN harness/comp_kdfchain_harness.c -lcrypto -o build/harness/comp_kdfchain \
    && clang $SAN harness/seq_aead_harness.c -lcrypto -o build/harness/seq_aead

# Stage 2.3 PQC cross-library differential: PQClean is a lightweight header/C
# reference build, so we include it (and its self-test runs in negative_tests).
# The deterministic NIST-KAT byte-exact cross-check reuses the same liboqs +
# PQClean builds (no extra heavy deps), so build it here too.
RUN bash scripts/build_pqc_diff.sh \
    && bash scripts/build_pqc_kat.sh

# Stage 2.4 cross-language differentials: Go crypto + RustCrypto backends. Both
# toolchains are in the image, so build both (their self-tests run in
# negative_tests below).
RUN bash scripts/build_go_diff.sh \
    && bash scripts/build_rust_diff.sh

# Stage 3 ecosystem: PyCryptodome (Python) + libgcrypt (GnuPG) + nettle (GnuTLS)
# + Bouncy Castle (Java) cross-library differentials; self-tests run in
# negative_tests below. build_java_diff.sh fetches the pinned BC provider jar.
RUN bash scripts/build_py_diff.sh \
    && bash scripts/build_gcrypt_diff.sh \
    && bash scripts/build_nettle_diff.sh \
    && bash scripts/build_java_diff.sh

# Sanity-check the oracles actually fire on injected faults at image-build time.
RUN bash tests/negative_tests.sh

CMD ["bash"]
