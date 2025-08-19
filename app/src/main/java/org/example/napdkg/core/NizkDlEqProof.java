package org.example.napdkg.core;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.HashingTools;

/**
 * Non‑interactive zero‑knowledge proof of equality of discrete logs (DLEQ)
 * in the context of DHPVSS.
 *
 * <p>
 * This proves knowledge of α ∈ ℤₚ such that simultaneously
 * x = [α]·G and y = [α]·h
 * for two bases G,h ∈ 𝔾, without revealing α.
 *
 * <p>
 * In DHPVSS distribution:
 * <ul>
 * <li>G = group generator</li>
 * <li>h = secondary base (e.g. the weighted aggregate U)</li>
 * <li>x = dealer’s public key = [skD]·G</li>
 * <li>y = weighted aggregate V = [skD]·h</li>
 * <li>α = dealer’s secret key skD ∈ ℤₚ</li>
 * </ul>
 */
public class NizkDlEqProof {
    private final BigInteger challenge; // e ∈ ℤₚ
    private final BigInteger response; // z ∈ ℤₚ

    public NizkDlEqProof(BigInteger challenge, BigInteger response) {
        this.challenge = challenge;
        this.response = response;
    }

    public BigInteger getChallenge() {
        return challenge;
    }

    public BigInteger getResponse() {
        return response;
    }

    @Override
    public String toString() {
        return "NizkDlEqProof{e=" + challenge + ", z=" + response + "}";
    }

    public static NizkDlEqProof fromHex(String eHex, String zHex) {
        BigInteger e = new BigInteger(eHex, 16);
        BigInteger z = new BigInteger(zHex, 16);
        return new NizkDlEqProof(e, z);
    }

    private static final SecureRandom RNG = new SecureRandom();

    /**
     * Generate a DLEQ proof for α ∈ ℤₚ satisfying x = [α]·G and y = [α]·h.
     *
     * <ol>
     * <li>Pick random w ∈R [1, p−1]</li>
     * <li>a₁ = [w]·G, a₂ = [w]·h</li>
     * <li>H = Hash(G, x, h, y, a₁, a₂) mod p</li>
     * <li>Use H as seed for SHA1PRNG → challenge e ∈R [1, p−1]</li>
     * <li>response z = w − e·α (mod p)</li>
     * </ol>
     *
     * @param ctx   DHPVSS context (provides G and subgroup order p)
     * @param h     secondary base h ∈ 𝔾
     * @param x     = [α]·G ∈ 𝔾
     * @param y     = [α]·h ∈ 𝔾
     * @param alpha secret α ∈ ℤₚ
     * @return challenge/response pair (e,z)
     */
    public static NizkDlEqProof generateProof(
            DkgContext ctx,
            ECPoint x,
            ECPoint h,
            ECPoint y,
            BigInteger alpha) {
        BigInteger p = ctx.getOrder();
        ECPoint G = ctx.getGenerator();

        // 1) random w ∈ [1, p−1]
        BigInteger w;
        do {
            w = new BigInteger(p.bitLength(), RNG);
        } while (w.signum() == 0 || w.compareTo(p) >= 0);

        // System.out.println(" [DLEQ] w = " + w.toString(16));

        // 2) commitments a1 = w·G, a2 = w·h
        ECPoint a1 = G.multiply(w).normalize();
        ECPoint a2 = h.multiply(w).normalize();
        // System.out.println(" [DLEQ] a1 = " + a1);
        // System.out.println(" [DLEQ] a2 = " + a2);

        // 3) H = Hash(G, x, h, y, a1, a2) mod p
        BigInteger H = HashingTools
                .hashElements(ctx, G, x, h, y, a1, a2)
                .mod(p);
        // System.out.println(" [DLEQ] H = " + H.toString(16));
        // 4) challenge e ← PRG(H) in [1, p−1]
        SecureRandom prg;
        try {
            prg = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA1PRNG unavailable", ex);
        }
        prg.setSeed(H.toByteArray());
        BigInteger e;
        do {
            e = new BigInteger(p.bitLength(), prg);
        } while (e.signum() == 0 || e.compareTo(p) >= 0);
        // System.out.println(" [DLEQ] e = " + e.toString(16));

        // 5) z = w − e·α mod p
        BigInteger z = w.subtract(e.multiply(alpha)).mod(p);
        // System.out.println(" [DLEQ] z = " + z.toString(16));

        return new NizkDlEqProof(e, z);
    }

    /**
     * Verify a DLEQ proof for x=[α]·G, y=[α]·h.
     *
     * <ol>
     * <li>a₁' = [z]·G + [e]·x</li>
     * <li>a₂' = [z]·h + [e]·y</li>
     * <li>H' = Hash(G, x, h, y, a₁', a₂') mod p</li>
     * <li>e' ← PRG(H')</li>
     * <li>Accept iff e' == e (from proof)</li>
     * </ol>
     *
     * @param ctx DHPVSS context
     * @param h   secondary base h ∈ 𝔾
     * @param x   public key = [α]·G
     * @param y   aggregate = [α]·h
     * @param prf proof (e,z)
     * @return true iff proof checks out
     */
    public static boolean verifyProof(
            DkgContext ctx,
            ECPoint x,
            ECPoint h,
            ECPoint y,
            NizkDlEqProof prf) {
        BigInteger p = ctx.getOrder();
        ECPoint G = ctx.getGenerator();

        BigInteger e = prf.getChallenge();
        BigInteger z = prf.getResponse();
        x = x.normalize();
        h = h.normalize();
        y = y.normalize();

        // 1) a₁' = z·G + e·x
        ECPoint a1p = G.multiply(z).add(x.multiply(e)).normalize();
        // System.out.println(" [DLEQ.verify] recomputed a1′ = " + a1p);
        // a₂' = z·h + e·y
        ECPoint a2p = h.multiply(z).add(y.multiply(e)).normalize();
        // System.out.println(" [DLEQ.verify] recomputed a2′ = " + a2p);
        // 2) H' = Hash(G,x,h,y,a₁',a₂') mod p
        BigInteger Hp = HashingTools
                .hashElements(ctx, G, x, h, y, a1p, a2p)
                .mod(p);
        // System.out.println(" [DLEQ.verify] H1′ = " + Hp.toString(16));

        // 3) e' ← PRG(H')
        SecureRandom prg;
        try {
            prg = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA1PRNG unavailable", ex);
        }
        prg.setSeed(Hp.toByteArray());
        BigInteger e2;
        do {
            e2 = new BigInteger(p.bitLength(), prg);
        } while (e2.signum() == 0 || e2.compareTo(p) >= 0);
        // System.out.println(" [DLEQ.verify] e′ recomputed = " + e2);
        // 4) accept iff e2 == e
        return e2.equals(e);

    }

}
