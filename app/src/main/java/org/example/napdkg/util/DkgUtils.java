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

    // DkgUtils
    // public static List<PublicKeysWithProofs> fetchAllEphemeralPubs(
    // DkgContext ctx, PbbClient pbb, int n) throws Exception {

    // PublicKeysWithProofs[] byIndex = new PublicKeysWithProofs[n];
    // int seen = 0;

    // while (seen < n) {
    // for (EphemeralKeyDTO dto : pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class))
    // {
    // int idx = dto.partyIndex;
    // if (idx < 0 || idx >= n || byIndex[idx] != null)
    // continue;

    // ECPoint P = ctx.getGenerator().getCurve()
    // .decodePoint(org.bouncycastle.util.encoders.Hex.decode(dto.publicKey))
    // .normalize();

    // String[] parts = dto.schnorrProof.split("\\|");
    // if (parts.length != 2)
    // throw new IllegalStateException("Bad schnorrProof format");
    // BigInteger c = new BigInteger(parts[0], 16);
    // BigInteger z = new BigInteger(parts[1], 16);
    // NizkDlProof prf = new NizkDlProof(c, z);

    // if (!NizkDlProof.verifyProof(ctx, P, prf))
    // throw new IllegalStateException("Invalid Schnorr proof for party " + idx);

    // byIndex[idx] = new PublicKeysWithProofs(idx, P, prf);
    // seen++;
    // }
    // if (seen < n)
    // Thread.sleep(10);
    // }
    // return
    // java.util.Collections.unmodifiableList(java.util.Arrays.asList(byIndex));
    // }

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

}
