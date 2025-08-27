package org.example.napdkg.util;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECPoint;

public class HashingTools {

    /**
     * Hashes a single group element P ∈ 𝔾 to Zₚ via SHA‑256.
     *
     * @param point the ECPoint P in the elliptic‐curve group 𝔾
     * @return H(P) interpreted as a nonnegative BigInteger (i.e. ∈ Zₚ)
     */
    public static BigInteger hashECPoint(ECPoint point) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encoded = point.getEncoded(true); // compressed form
            digest.update(encoded);
            byte[] hashBytes = digest.digest();
            return new BigInteger(1, hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    public static byte[] hashECPointToBytes(ECPoint point) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encoded = point.getEncoded(true); // compressed form
            digest.update(encoded);
            byte[] hashBytes = digest.digest();
            return hashBytes;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Hashes a sequence of group elements [P₁…P_k]∈𝔾 by concatenating their
     * compressed encodings, then SHA‑256.
     *
     * @param points the ECPoints P₁…P_k
     * @return H(P₁ ∥ … ∥ P_k) as a nonnegative BigInteger
     */
    public static BigInteger hashECPoints(ECPoint... points) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (ECPoint point : points) {
                byte[] encoded = point.getEncoded(true);
                digest.update(encoded);
            }
            byte[] hashBytes = digest.digest();
            return new BigInteger(1, hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Builds a pseudo‐random polynomial m*(X) ∈ Zₚ[X] for the SCRAPE dual‐code
     * test.
     *
     * 1. d₀ ← H( pk_D ∥ E₁ ∥ … ∥ E_n ∥ C₁ ∥ … ∥ C_n )
     * 2. dᵢ ← H(dᵢ₋₁) for i = 1…numPolyCoeffs−1
     * 
     * These coefficients feed into the SCRAPE check via evaluations at αᵢ.
     *
     * @param dealerPub       dealer’s EC public key pk_D
     * @param comKeys         array of ephemeral keys Eᵢ
     * @param encryptedShares array of encrypted shares Cᵢ
     * @param numPolyCoeffs   number of coefficients to output (degree+1)
     * @param modulus         the prime p = |𝔾| for reduction
     * @return [d₀…d_{numPolyCoeffs−1}] ∈ Zₚ^{numPolyCoeffs}
     */
    public static BigInteger[] hashPointsToPoly(ECPoint dealerPub,
            ECPoint[] comKeys,
            ECPoint[] encryptedShares,
            int numPolyCoeffs,
            BigInteger modulus, DkgContext ctx) {
        // 1) seed ← H(pk_D ∥ E₁…E_n ∥ C₁…C_n) mod p
        BigInteger listDigest1 = hashECPoint(dealerPub);
        BigInteger listDigest2 = hashECPoints(comKeys);
        BigInteger listDigest3 = hashECPoints(encryptedShares);

        // 2) initial coefficient
        BigInteger initialCoeff = hashBigIntegers(ctx, listDigest1, listDigest2, listDigest3)
                .mod(modulus);

        // 3) extend by hashing previous
        BigInteger[] polyCoeffs = new BigInteger[numPolyCoeffs];
        polyCoeffs[0] = initialCoeff;
        for (int i = 1; i < numPolyCoeffs; i++) {
            polyCoeffs[i] = hashBigIntegers(ctx, polyCoeffs[i - 1]).mod(modulus);
        }
        return polyCoeffs;
    }

    /**
     * Compressed ECPoint → byte[] helper.
     */
    private static byte[] encodeECPoint(ECPoint point) {
        return point.getEncoded(true);
    }

    /**
     * Pads or trims a BigInteger’s byte[] to exactly length bytes.
     *
     * @param n      the BigInteger to encode
     * @param length desired output length
     * @return fixed‐length big‐endian byte array
     */
    private static byte[] toFixedLength(BigInteger n, int length) {
        byte[] raw = n.toByteArray();
        if (raw.length == length) {
            return raw;
        } else if (raw.length > length) {
            byte[] trimmed = new byte[length];
            System.arraycopy(raw, raw.length - length, trimmed, 0, length);
            return trimmed;
        } else {
            byte[] padded = new byte[length];
            System.arraycopy(raw, 0, padded, length - raw.length, raw.length);
            return padded;
        }
    }

    /**
     * Hashes fixed‐length encodings of field elements z₁…z_k ∈ Zₚ to Zₚ.
     *
     * Useful for chaining scalars into a single digest (e.g. polynomial seeds).
     *
     * @param bns the BigIntegers z₁…z_k
     * @return SHA-256(z₁ … z_k) as nonnegative BigInteger
     */
    public static BigInteger hashBigIntegers(DkgContext ctx, BigInteger... bns) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // derive a uniform block size from the first input
            int len = (ctx.getOrder().bitLength() + 7) / 8;
            for (BigInteger bn : bns) {
                byte[] chunk = toFixedLength(bn, len);
                digest.update(chunk);
            }
            byte[] hash = digest.digest();
            return new BigInteger(1, hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-256 algorithm not available", ex);
        }
    }

    /**
     * Hashes the six points (g, x, h, y, a1, a2) for the DLEQ proof χ.
     *
     * χ = SHA-256( compress(g) ∥ compress(x) ∥ compress(h)
     * ∥ compress(y) ∥ compress(a1) ∥ compress(a2) )
     *
     * @param ctx context for curve parameters
     * @param g   generator G
     * @param x   base public (e.g. pk_D)
     * @param h   second base (e.g. U)
     * @param y   second value (e.g. V)
     * @param a1  commitment g^w
     * @param a2  commitment h^w
     * @return χ as nonnegative BigInteger
     */
    public static BigInteger hashElements(DkgContext ctx,
            org.bouncycastle.math.ec.ECPoint g,
            org.bouncycastle.math.ec.ECPoint x,
            org.bouncycastle.math.ec.ECPoint h,
            org.bouncycastle.math.ec.ECPoint y,
            org.bouncycastle.math.ec.ECPoint a1,
            org.bouncycastle.math.ec.ECPoint a2) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(encodeECPoint(g));
            digest.update(encodeECPoint(x));
            digest.update(encodeECPoint(h));
            digest.update(encodeECPoint(y));
            digest.update(encodeECPoint(a1));
            digest.update(encodeECPoint(a2));
            byte[] hash = digest.digest();

            // System.out.println("[hashElements] hash = " + Hex.toHexString(hash));

            return new BigInteger(1, hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-256 algorithm not available", ex);
        }
    }

    /**
     * Demonstration of deriving a random polynomial m^*(X),
     * with zero external "helper" methods for compression or fixed-length output.
     */
    public static BigInteger[] deriveMStar(
            DkgContext ctx,
            ECPoint pk_i, // ephemeral pubkey of the dealer, optionally
            ECPoint[] E, // ephemeral pubkeys of others
            ECPoint[] Cij, // masked shares
            BigInteger[] CHat, // masked scalars
            int n,
            int t) throws NoSuchAlgorithmException {

        // (A) Decide the polynomial degree for "SCRAPE" style.
        // If the protocol says deg = n - t - 1, do that: OBS only works with deg: n - t
        // - 2.
        int deg = n - t - 2;
        int numCoeffs = deg + 1;

        // (B) We'll gather all data in a ByteArrayOutputStream
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        // 1) pk_i (compressed). If pk_i is not needed or is null, skip this.
        if (pk_i != null) {
            byte[] pkComp = pk_i.getEncoded(true); // compressed form => 33 bytes
            bos.write(pkComp, 0, pkComp.length);
        }

        // 2) E array: ephemeral pubkeys, each compressed => 33 bytes
        for (ECPoint e : E) {
            byte[] compE = e.getEncoded(true);
            bos.write(compE, 0, compE.length);
        }

        // 3) Cij array: masked shares, each also an EC point, so also compressed
        for (ECPoint c : Cij) {
            byte[] compC = c.getEncoded(true);
            bos.write(compC, 0, compC.length);
        }

        // 4) CHat array: each is a BigInteger. We convert to exactly 32 bytes.
        for (BigInteger x : CHat) {
            // Convert x to byte[] with no sign bit => new BigInteger(1, ...) if needed
            // Then ensure exactly 32 bytes, zero-padded if smaller.
            byte[] raw = x.toByteArray(); // can be 1..33 bytes if positive
            // We'll keep only the last 32 bytes if it's bigger, or pad if it's smaller.
            byte[] fixed32 = new byte[32];
            // Copy from the end of 'raw' into the end of 'fixed32'
            int copyLen = Math.min(raw.length, 32);
            int srcPos = raw.length - copyLen;
            int destPos = 32 - copyLen;
            System.arraycopy(raw, srcPos, fixed32, destPos, copyLen);

            bos.write(fixed32, 0, 32);
        }

        // (C) Now compute a single SHA-256 over bos.toByteArray()
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] seed = sha256.digest(bos.toByteArray());

        // (D) Expand that seed into a polynomial's coefficients
        // We'll produce deg+1 coefficients: mStar[0..deg].
        BigInteger p = ctx.getOrder(); // Subgroup order
        BigInteger[] mStar = new BigInteger[numCoeffs];

        // Coefficient 0 is seed mod p
        mStar[0] = new BigInteger(1, seed).mod(p);

        // For i=1..deg, append a one-byte counter to 'seed' and hash again.
        for (int i = 1; i <= deg; i++) {
            ByteArrayOutputStream bos2 = new ByteArrayOutputStream(seed.length + 1);
            bos2.write(seed, 0, seed.length);
            bos2.write(i); // single byte counter

            byte[] digest = sha256.digest(bos2.toByteArray());
            mStar[i] = new BigInteger(1, digest).mod(p);
        }

        return mStar;
    }

    /**
     * Overload: hash (g, pub, A) for a single‐base DL proof.
     *
     * SHA-256( compress(g) ∥ compress(pub) ∥ compress(A) )
     */
    public static BigInteger hashElements(DkgContext ctx,
            org.bouncycastle.math.ec.ECPoint pub,
            org.bouncycastle.math.ec.ECPoint A) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(encodeECPoint(ctx.getGenerator()));
            digest.update(encodeECPoint(pub));
            digest.update(encodeECPoint(A));
            byte[] hash = digest.digest();
            return new BigInteger(1, hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-256 algorithm not available", ex);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Helper: compress an ECPoint to exactly 33 bytes (0x02/0x03 || 32-byte X
    // coordinate).
    private static byte[] compressTo33(ECPoint P) {
        // assume P is normalized. getEncoded(true) always yields 1 + 32 bytes on
        // secp256r1.
        byte[] raw = P.normalize().getEncoded(true);
        if (raw.length != 33) {
            throw new IllegalStateException("Expected 33-byte compressed ECPoint, got " + raw.length);
        }
        return raw;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Helper: turn any BigInteger into exactly 32 bytes (big-endian).
    private static byte[] toFixed32(BigInteger x) {
        byte[] raw = x.toByteArray();
        if (raw.length == 32) {
            return raw;
        } else if (raw.length == 33 && raw[0] == 0x00) {
            // leading zero, drop it
            return Arrays.copyOfRange(raw, 1, 33);
        } else if (raw.length < 32) {
            // left-pad with zero bytes
            byte[] out = new byte[32];
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
            return out;
        } else {
            // too long (shouldn’t happen if x < p < 2^256), but just take the low 32 bytes:
            return Arrays.copyOfRange(raw, raw.length - 32, raw.length);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Helper: standard hex‐encoder (lowercase).
    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Helper: route debug prints through your logger (or System.out).
    private static void logDebug(String msg) {
        // Replace “System.out.println” with your logger.debug(...) if you have SLF4J or
        // logback available.
        System.out.println(msg);
    }
}
