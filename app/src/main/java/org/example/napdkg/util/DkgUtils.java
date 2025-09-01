// src/main/java/org/example/napdkg/util/DkgUtils.java
package org.example.napdkg.util;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.core.NizkDlProof;
import org.example.napdkg.core.PublicKeysWithProofs;
import org.example.napdkg.core.Share;
import org.example.napdkg.dto.EphemeralKeyDTO;

public final class DkgUtils {
    public static final int POLL_MS = 100;

    private DkgUtils() {
        /* no-op */ }

    // —— point/scalar codecs —— //

    public static String encodePoint(ECPoint P) {
        return Hex.toHexString(P.normalize().getEncoded(true));
    }

    public static String encodeScalar(BigInteger x) {
        return x.toString(16);
    }

    public static String[] encodePoints(ECPoint[] pts) {
        String[] out = new String[pts.length];
        for (int i = 0; i < pts.length; i++) {
            out[i] = encodePoint(pts[i]);
        }
        return out;
    }

    public static String[] encodeScalars(BigInteger[] xs) {
        String[] out = new String[xs.length];
        for (int i = 0; i < xs.length; i++) {
            out[i] = encodeScalar(xs[i]);
        }
        return out;
    }

    /**
     * Polls the PBB every DEFAULT_POLL_MS until one DTO matching
     * `selector` appears, then applies `decoder` and returns the result.
     */
    // in DkgUtils.java
    public static <D, T> T waitForAndDecode(
            PbbClient pbb,
            String topic,
            Class<D> dtoClass,
            Predicate<D> selector,
            Function<D, T> decoder) throws Exception {
        while (true) {
            Thread.sleep(POLL_MS);
            for (D dto : pbb.fetch(topic, dtoClass)) {
                if (!selector.test(dto))
                    continue;
                return decoder.apply(dto);
            }
        }
    }

    public static ECPoint[] computeCommitments(
            DkgContext ctx,
            Share[] shares,
            List<PublicKeysWithProofs> pubs,
            BigInteger ski) {
        int n = shares.length;
        ECPoint[] Cij = new ECPoint[n];
        for (int j = 0; j < n; j++) {
            ECPoint Ej = pubs.get(j).getPublicKey();
            ECPoint Aij = shares[j].getAiPoint();
            Cij[j] = Ej.multiply(ski).add(Aij).normalize();
        }
        return Cij;
    }

    /** compute Ĉᵢⱼ = H′(Aᵢⱼ) ⊕ aᵢⱼ for all j */
    public static BigInteger[] computeMasks(
            DkgContext ctx,
            Share[] shares) {
        int n = shares.length;
        BigInteger[] CHat = new BigInteger[n];
        BigInteger order = ctx.getOrder();
        for (int j = 0; j < n; j++) {
            ECPoint Aij = shares[j].getAiPoint();
            BigInteger aij = shares[j].getai();
            CHat[j] = MaskedShareCHat.maskShare(Aij, aij, order);
        }
        return CHat;
    }

    /** aggregate U = ∑ vⱼ·Eⱼ, V = ∑ vⱼ·Cⱼⱼ */
    public static class Aggregation {
        public final ECPoint U, V;

        public Aggregation(ECPoint U, ECPoint V) {
            this.U = U;
            this.V = V;
        }
    }

    // 1) Arrival-order list (exactly what dealers used when constructing E[])
    public static List<PublicKeysWithProofs> fetchEphemeralPubsByArrival(
            DkgContext ctx, PbbClient pbb) throws Exception {
        List<EphemeralKeyDTO> dtos = pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class);

        List<PublicKeysWithProofs> pubs = new ArrayList<>(dtos.size());
        for (EphemeralKeyDTO dto : dtos) {
            ECPoint P = ctx.getGenerator().getCurve()
                    .decodePoint(org.bouncycastle.util.encoders.Hex.decode(dto.publicKey))
                    .normalize();

            String[] parts = dto.schnorrProof.split("\\|");
            if (parts.length != 2)
                throw new IllegalStateException("Bad schnorrProof format");
            BigInteger c = new BigInteger(parts[0], 16);
            BigInteger z = new BigInteger(parts[1], 16);
            NizkDlProof prf = new NizkDlProof(c, z);

            if (!NizkDlProof.verifyProof(ctx, P, prf))
                throw new IllegalStateException("Invalid Schnorr proof for partyIndex=" + dto.partyIndex);

            pubs.add(new PublicKeysWithProofs(dto.partyIndex, P, prf));
        }
        // IMPORTANT: do NOT sort here; preserve PBB arrival order
        return pubs;
    }

    // 2) Direct lookup by party index (for Θ verification)
    public static ECPoint getEphemeralPubByIndex(
            DkgContext ctx, PbbClient pbb, int partyIndex) throws Exception {
        for (EphemeralKeyDTO dto : pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class)) {
            if (dto.partyIndex == partyIndex) {
                ECPoint P = ctx.getGenerator().getCurve()
                        .decodePoint(org.bouncycastle.util.encoders.Hex.decode(dto.publicKey))
                        .normalize();

                String[] parts = dto.schnorrProof.split("\\|");
                if (parts.length != 2)
                    throw new IllegalStateException("Bad schnorrProof format");
                BigInteger c = new BigInteger(parts[0], 16);
                BigInteger z = new BigInteger(parts[1], 16);
                NizkDlProof prf = new NizkDlProof(c, z);

                if (!NizkDlProof.verifyProof(ctx, P, prf))
                    throw new IllegalStateException("Invalid Schnorr proof for partyIndex=" + partyIndex);

                return P;
            }
        }
        throw new IllegalStateException("Missing ephemeral key for partyIndex=" + partyIndex);
    }

    public static List<PublicKeysWithProofs> fetchAllEphemeralPubs(
            DkgContext ctx, PbbClient pbb, int n) throws Exception {
        List<EphemeralKeyDTO> dtos = pbb.fetch("ephemeralKeys",
                EphemeralKeyDTO.class);
        List<PublicKeysWithProofs> pubs = new ArrayList<>(dtos.size());
        for (EphemeralKeyDTO dto : dtos) {
            byte[] raw = Hex.decode(dto.publicKey);
            ECPoint P = ctx.getGenerator()
                    .getCurve()
                    .decodePoint(raw)
                    .normalize();

            String[] parts = dto.schnorrProof.split("\\|");
            BigInteger challenge = new BigInteger(parts[0], 16);
            BigInteger response = new BigInteger(parts[1], 16);
            NizkDlProof proof = new NizkDlProof(challenge, response);
            Boolean verify = NizkDlProof.verifyProof(ctx, P, proof);
            if (verify == true) {
                pubs.add(new PublicKeysWithProofs(dto.partyIndex, P, proof));
            } else {
                throw new IllegalStateException("DL proof " + verify);
            }
        }
        // if you really want to _block_ until you have n, you can loop here
        return pubs;
    }

    // * Simple SCRAPE dual‐code weights:
    // *
    // * v_j = ∏_{k=1, k≠j}^n (α[j] - α[k])^{-1} (mod p),
    // * for j=1..n.
    // *
    // * @param p prime modulus
    // * @param alphas array of length (n+1), where alphas[0]=0 unused, and
    // * alphas[1..n] are distinct
    // * @param n total number of participants
    // * @return BigInteger[n] = { v₁, v₂, …, vₙ } (zero‐based array)
    // */
    public static BigInteger[] deriveShrapeCoeffs(
            BigInteger p,
            BigInteger[] alphas,
            int n) {
        BigInteger[] v = new BigInteger[n];
        for (int j = 1; j <= n; j++) {
            BigInteger prod = BigInteger.ONE;
            for (int k = 1; k <= n; k++) {
                if (j == k)
                    continue;
                // diff = α[j] - α[k] (mod p)
                BigInteger diff = alphas[j].subtract(alphas[k]).mod(p);
                // invert mod p
                BigInteger inv = diff.modInverse(p);
                prod = prod.multiply(inv).mod(p);
            }
            v[j - 1] = prod; // store into zero‐based array slot
        }
        return v;
    }

    /**
     * Evaluate the hash‑derived polynomial m*(X) at a single point αᵢ:
     *
     * m*(αᵢ) = ∑_{j=0}^{d} cⱼ·(αᵢ)^j mod p
     *
     * @param c polynomial coefficients [c₀…c_d]
     * @param α evaluation point αᵢ
     * @param p subgroup order (prime modulus)
     * @return the field value m*(αᵢ)
     */
    public static BigInteger evaluatePolynomial(BigInteger[] c, BigInteger α, BigInteger p) {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPow = BigInteger.ONE;
        for (BigInteger coeff : c) {
            result = result.add(coeff.multiply(xPow)).mod(p);
            xPow = xPow.multiply(α).mod(p);
        }
        return result;
    }

    /**
     * Batch‑evaluate m*(X) at all α[1…n]:
     *
     * @param c polynomial coefficients [c₀…c_d]
     * @param α evaluation points [0…n]
     * @param p subgroup order (prime modulus)
     * @return array evals[0…n] with evals[i] = m*(α[i]) (note index 0 is unused)
     */
    public static BigInteger[] evalAll(BigInteger[] c, BigInteger[] α, BigInteger p) {
        BigInteger[] out = new BigInteger[α.length];
        for (int i = 1; i < α.length; i++) {
            out[i] = evaluatePolynomial(c, α[i], p);
        }
        return out;
    }

}
