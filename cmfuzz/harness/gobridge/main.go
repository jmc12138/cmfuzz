// CMFuzz stage 2.4 — Go crypto cross-language differential backend.
//
// A drop-in backend for the subprocess differential runner (diff_subproc): it
// speaks the exact same wire protocol as the C compute CLIs (compute_common.h)
// — one "<op> <hex-blob>" request per stdin line, one hex (or "01"/"00" verdict,
// or "NA"/"ERR") response per stdout line — but computes every primitive with
// Go's standard library + golang.org/x/crypto instead of a C library. Because
// Go's crypto stack is an independent implementation lineage (not derived from
// OpenSSL/BoringSSL), byte-for-byte agreement against the OpenSSL reference is a
// genuine cross-language O1 differential.
//
// Build-injected faultMode=1 (see build_go_diff.sh) corrupts the first output
// so the negative self-test can prove the differential catches a divergence.
package main

import (
	"bufio"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

const (
	keyLen   = 32
	nonceLen = 12
	rsaPubE  = 65537
	saltLen  = 32
	hkdfOut  = 42
	pbkdf2DK = 32
	pbkdf2It = 4096
)

var faultMode = "0"

type vec struct {
	op   int
	key  []byte
	msg  []byte
	aad  []byte
}

// parseBlob mirrors cmf_vec_parse: key(32) || nonce(12) || aadlen(2 BE) || aad || msg.
func parseVec(op int, blob []byte) vec {
	need := keyLen + nonceLen + 2
	if len(blob) < need {
		return vec{op: op, msg: blob}
	}
	key := blob[:keyLen]
	p := blob[keyLen+nonceLen:]
	aadlen := int(p[0])<<8 | int(p[1])
	rest := blob[need:]
	if aadlen > len(rest) {
		aadlen = len(rest)
	}
	return vec{op: op, key: key, aad: rest[:aadlen], msg: rest[aadlen:]}
}

// parseVerifyPayload mirrors cmf_verify_parse: publen(2) || pub || siglen(2) || sig || msg.
func parseVerifyPayload(p []byte) (pub, sig, msg []byte, ok bool) {
	if len(p) < 2 {
		return nil, nil, nil, false
	}
	pl := int(p[0])<<8 | int(p[1])
	off := 2
	if off+pl+2 > len(p) {
		return nil, nil, nil, false
	}
	pub = p[off : off+pl]
	off += pl
	sl := int(p[off])<<8 | int(p[off+1])
	off += 2
	if off+sl > len(p) {
		return nil, nil, nil, false
	}
	sig = p[off : off+sl]
	off += sl
	msg = p[off:]
	return pub, sig, msg, true
}

// compute returns the hex/verdict response for one request, or ("", false) => "NA".
func compute(v vec) (string, bool) {
	switch v.op {
	case 0:
		h := sha256.Sum256(v.msg)
		return hex.EncodeToString(h[:]), true
	case 1:
		h := sha512.Sum512(v.msg)
		return hex.EncodeToString(h[:]), true
	case 2:
		m := hmac.New(sha256.New, v.key)
		m.Write(v.msg)
		return hex.EncodeToString(m.Sum(nil)), true
	// ops 3 (ChaCha20-Poly1305) and 4 (AES-256-GCM) need the nonce, which
	// parseVec drops; they are handled in dispatch()/aeadFromBlob().
	case 5:
		h := sha3.Sum256(v.msg)
		return hex.EncodeToString(h[:]), true
	case 6:
		h := sha3.Sum512(v.msg)
		return hex.EncodeToString(h[:]), true
	case 7:
		out := make([]byte, 32)
		sha3.ShakeSum128(out, v.msg)
		return hex.EncodeToString(out), true
	case 8:
		out := make([]byte, 64)
		sha3.ShakeSum256(out, v.msg)
		return hex.EncodeToString(out), true
	case 9:
		r := hkdf.New(sha256.New, v.msg, v.key, v.aad)
		out := make([]byte, hkdfOut)
		if _, err := readFull(r, out); err != nil {
			return "ERR", true
		}
		return hex.EncodeToString(out), true
	case 10:
		out := pbkdf2.Key(v.msg, v.key, pbkdf2It, pbkdf2DK, sha256.New)
		return hex.EncodeToString(out), true
	case 11:
		if len(v.key) < keyLen {
			return "ERR", true
		}
		priv := ed25519.NewKeyFromSeed(v.key[:keyLen])
		return hex.EncodeToString(ed25519.Sign(priv, v.msg)), true
	case 12:
		if len(v.key) < keyLen || len(v.msg) < curve25519.PointSize {
			return "ERR", true
		}
		out, err := curve25519.X25519(v.key[:keyLen], v.msg[:curve25519.PointSize])
		if err != nil {
			return "ERR", true
		}
		return hex.EncodeToString(out), true
	case 13:
		return ecdsaVerify(v.msg), true
	case 14:
		return rsaPSSVerify(v.msg), true
	}
	return "", false
}

func ecdsaVerify(payload []byte) string {
	pub, sig, msg, ok := parseVerifyPayload(payload)
	if !ok {
		return "00"
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), pub)
	if x == nil {
		return "00"
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	h := sha256.Sum256(msg)
	if ecdsa.VerifyASN1(key, h[:], sig) {
		return "01"
	}
	return "00"
}

func rsaPSSVerify(payload []byte) string {
	pub, sig, msg, ok := parseVerifyPayload(payload)
	if !ok {
		return "00"
	}
	key := &rsa.PublicKey{N: new(big.Int).SetBytes(pub), E: rsaPubE}
	h := sha256.Sum256(msg)
	opts := &rsa.PSSOptions{SaltLength: saltLen, Hash: crypto.SHA256}
	if rsa.VerifyPSS(key, crypto.SHA256, h[:], sig, opts) == nil {
		return "01"
	}
	return "00"
}

func readFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	first := true
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			sp := strings.IndexByte(line, ' ')
			if sp > 0 {
				op, _ := strconv.Atoi(line[:sp])
				blob, herr := hex.DecodeString(line[sp+1:])
				var resp string
				if herr != nil {
					resp = "ERR"
				} else {
					// nonce lives at blob[32:44]; AEAD ops need it, so pass the
					// raw blob through a dedicated path.
					resp = dispatch(op, blob)
				}
				if faultMode == "1" && first && resp != "NA" {
					resp = "ff"
				}
				first = false
				out.WriteString(resp)
				out.WriteByte('\n')
			}
		}
		if err != nil {
			break
		}
	}
}

// dispatch handles the AEAD nonce (which parseVec drops) and defers everything
// else to compute().
func dispatch(op int, blob []byte) string {
	if op == 3 || op == 4 {
		return aeadFromBlob(op, blob)
	}
	v := parseVec(op, blob)
	resp, ok := compute(v)
	if !ok {
		return "NA"
	}
	return resp
}

func aeadFromBlob(op int, blob []byte) string {
	need := keyLen + nonceLen + 2
	if len(blob) < need {
		return "ERR"
	}
	key := blob[:keyLen]
	nonce := blob[keyLen : keyLen+nonceLen]
	p := blob[keyLen+nonceLen:]
	aadlen := int(p[0])<<8 | int(p[1])
	rest := blob[need:]
	if aadlen > len(rest) {
		aadlen = len(rest)
	}
	aad := rest[:aadlen]
	msg := rest[aadlen:]
	var aead cipher.AEAD
	var err error
	if op == 3 {
		aead, err = chacha20poly1305.New(key)
	} else {
		var blk cipher.Block
		blk, err = aes.NewCipher(key)
		if err == nil {
			aead, err = cipher.NewGCM(blk)
		}
	}
	if err != nil {
		return "ERR"
	}
	ct := aead.Seal(nil, nonce, msg, aad)
	return hex.EncodeToString(ct)
}
