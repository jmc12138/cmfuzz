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
# Microsoft SEAL, and BoringSSL (stage-2.1 subprocess differential) are NOT built
# here to keep the image small/fast; run scripts/build_diff_libs.sh,
# scripts/build_seal.sh, or scripts/build_subproc.sh inside the container if you
# need the differential (O1), FHE, or BoringSSL harnesses. Go is preinstalled so
# build_subproc.sh (which builds BoringSSL) works on demand.
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
        build-essential \
        autoconf \
        automake \
        libtool \
        pkg-config \
        golang-go \
    && rm -rf /var/lib/apt/lists/*

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

# Sanity-check the oracles actually fire on injected faults at image-build time.
RUN bash tests/negative_tests.sh

CMD ["bash"]
