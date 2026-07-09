/*
 * CMFuzz stage 3 subprocess differential backend — Bouncy Castle (Java).
 *
 * A standalone JVM program implementing the same wire protocol as the C/Go/Rust/
 * Python subprocess backends (harness/subproc/compute_common.h): read "<op> <hex>"
 * lines from stdin, where hex = key(32) || nonce(12) || aadlen(2, BE) || aad ||
 * msg, and print the hex result (or "ERR") per line.
 *
 * Bouncy Castle is a pure-Java implementation, so byte-exact agreement with the
 * OpenSSL reference is a real cross-language O1 differential — Java becomes a
 * fifth independent lineage (after OpenSSL/Go/Rust/Python). All 15 ops (0-14)
 * are implemented via BC's JCA provider and low-level lightweight API.
 *
 * CMF_JAVA_FAULT=1 in the environment flips the first output byte on every reply
 * so the negative self-test can prove the differential catches a divergence.
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

public final class CmfCompute {
    static final int KEYLEN = 32, NONCELEN = 12, TAGLEN = 16;
    static final boolean FAULT = "1".equals(System.getenv("CMF_JAVA_FAULT"));
    static final char[] HEX = "0123456789abcdef".toCharArray();

    static byte[] hexdec(String s) {
        int n = s.length() / 2;
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++)
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }
    static String hexenc(byte[] b, int len) {
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) { sb.append(HEX[(b[i] >> 4) & 15]); sb.append(HEX[b[i] & 15]); }
        return sb.toString();
    }
    static byte[] slice(byte[] a, int off, int len) {
        byte[] r = new byte[len]; System.arraycopy(a, off, r, 0, len); return r;
    }

    // Parsed request fields (mirrors cmf_vec_parse).
    static final class Vec { byte[] key, nonce, aad, msg; }
    static Vec parse(byte[] blob) {
        Vec v = new Vec();
        int need = KEYLEN + NONCELEN + 2;
        if (blob.length < need) {
            v.key = new byte[KEYLEN]; v.nonce = new byte[NONCELEN];
            v.aad = new byte[0]; v.msg = blob; return v;
        }
        v.key = slice(blob, 0, KEYLEN);
        v.nonce = slice(blob, KEYLEN, NONCELEN);
        int p = KEYLEN + NONCELEN;
        int aadlen = ((blob[p] & 0xFF) << 8) | (blob[p + 1] & 0xFF);
        int rest = blob.length - need;
        if (aadlen > rest) aadlen = rest;
        v.aad = slice(blob, need, aadlen);
        v.msg = slice(blob, need + aadlen, rest - aadlen);
        return v;
    }

    static byte[][] parseVerify(byte[] p) {
        int pl = ((p[0] & 0xFF) << 8) | (p[1] & 0xFF);
        int off = 2;
        byte[] pub = slice(p, off, pl); off += pl;
        int sl = ((p[off] & 0xFF) << 8) | (p[off + 1] & 0xFF); off += 2;
        byte[] sig = slice(p, off, sl); off += sl;
        byte[] msg = slice(p, off, p.length - off);
        return new byte[][]{ pub, sig, msg };
    }

    static byte[] aead(String cipher, String keyAlg, Vec v, boolean gcm) throws Exception {
        Cipher c = Cipher.getInstance(cipher, "BC");
        SecretKeySpec ks = new SecretKeySpec(v.key, keyAlg);
        if (gcm) c.init(Cipher.ENCRYPT_MODE, ks, new GCMParameterSpec(TAGLEN * 8, v.nonce));
        else     c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(v.nonce));
        if (v.aad.length > 0) c.updateAAD(v.aad);
        return c.doFinal(v.msg);   // ciphertext || tag
    }

    static byte[] compute(int op, byte[] blob) throws Exception {
        Vec v = parse(blob);
        switch (op) {
            case 0: return java.security.MessageDigest.getInstance("SHA-256", "BC").digest(v.msg);
            case 1: return java.security.MessageDigest.getInstance("SHA-512", "BC").digest(v.msg);
            case 2: {
                Mac m = Mac.getInstance("HmacSHA256", "BC");
                m.init(new SecretKeySpec(v.key, "HmacSHA256"));
                return m.doFinal(v.msg);
            }
            case 3: return aead("ChaCha20-Poly1305", "ChaCha20", v, false);
            case 4: return aead("AES/GCM/NoPadding", "AES", v, true);
            case 5: return java.security.MessageDigest.getInstance("SHA3-256", "BC").digest(v.msg);
            case 6: return java.security.MessageDigest.getInstance("SHA3-512", "BC").digest(v.msg);
            case 7: {
                SHAKEDigest d = new SHAKEDigest(128);
                d.update(v.msg, 0, v.msg.length);
                byte[] o = new byte[32]; d.doFinal(o, 0, 32); return o;
            }
            case 8: {
                SHAKEDigest d = new SHAKEDigest(256);
                d.update(v.msg, 0, v.msg.length);
                byte[] o = new byte[64]; d.doFinal(o, 0, 64); return o;
            }
            case 9: {
                HKDFBytesGenerator g = new HKDFBytesGenerator(new SHA256Digest());
                g.init(new HKDFParameters(v.msg, v.key, v.aad));
                byte[] o = new byte[42]; g.generateBytes(o, 0, 42); return o;
            }
            case 10: {
                PKCS5S2ParametersGenerator g = new PKCS5S2ParametersGenerator(new SHA256Digest());
                g.init(v.msg, v.key, 4096);
                return ((KeyParameter) g.generateDerivedParameters(256)).getKey();
            }
            case 11: {
                Ed25519PrivateKeyParameters sk = new Ed25519PrivateKeyParameters(v.key, 0);
                Ed25519Signer s = new Ed25519Signer();
                s.init(true, sk);
                s.update(v.msg, 0, v.msg.length);
                return s.generateSignature();
            }
            case 12: {
                X25519PrivateKeyParameters sk = new X25519PrivateKeyParameters(v.key, 0);
                X25519PublicKeyParameters pk = new X25519PublicKeyParameters(v.msg, 0);
                X25519Agreement a = new X25519Agreement();
                a.init(sk);
                byte[] o = new byte[a.getAgreementSize()];
                a.calculateAgreement(pk, o, 0);
                return o;
            }
            case 13: {
                byte[][] parts = parseVerify(v.msg);
                ECNamedCurveParameterSpec sp = ECNamedCurveTable.getParameterSpec("P-256");
                ECPoint q = sp.getCurve().decodePoint(parts[0]);
                PublicKey pk = KeyFactory.getInstance("EC", "BC")
                        .generatePublic(new ECPublicKeySpec(q, sp));
                Signature s = Signature.getInstance("SHA256withECDSA", "BC");
                s.initVerify(pk);
                s.update(parts[2]);
                return new byte[]{ (byte) (s.verify(parts[1]) ? 1 : 0) };
            }
            case 14: {
                byte[][] parts = parseVerify(v.msg);
                RSAPublicKeySpec spec = new RSAPublicKeySpec(
                        new BigInteger(1, parts[0]), BigInteger.valueOf(65537));
                PublicKey pk = KeyFactory.getInstance("RSA", "BC").generatePublic(spec);
                Signature s = Signature.getInstance("SHA256withRSA/PSS", "BC");
                s.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
                        MGF1ParameterSpec.SHA256, 32, 1));
                s.initVerify(pk);
                s.update(parts[2]);
                return new byte[]{ (byte) (s.verify(parts[1]) ? 1 : 0) };
            }
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) continue;
            int sp = line.indexOf(' ');
            String rep;
            try {
                int op = Integer.parseInt(line.substring(0, sp));
                byte[] blob = hexdec(line.substring(sp + 1));
                byte[] res = compute(op, blob);
                if (res == null) rep = "NA";
                else {
                    if (FAULT && res.length > 0) res[0] ^= (byte) 0xFF;
                    rep = hexenc(res, res.length);
                }
            } catch (Exception e) {
                rep = "ERR";
            }
            System.out.println(rep);
            System.out.flush();
        }
    }
}
