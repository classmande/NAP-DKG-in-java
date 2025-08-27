package org.example.napdkg.core;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.math.ec.ECPoint;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.client.TopicPoller;
import org.example.napdkg.dto.EphemeralKeyDTO;
import org.example.napdkg.dto.ShareVerificationOutputDTO;
import org.example.napdkg.dto.SharingOutputDTO;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.DkgRef;
import org.example.napdkg.util.DkgUtils;
import org.example.napdkg.util.EvaluationTools;
import org.example.napdkg.util.HashingTools;
import org.example.napdkg.util.MaskedShareCHat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class for Share Verification (2nd round or after t + fa parties post Shi on
 * PBB.)
 * Follows 6 steps.
 */

public class VerificationPhase {
    private static final Logger log = LoggerFactory.getLogger(VerificationPhase.class);

    static final int POLL_MS = 100;

    private final PartyContext P;

    private final DkgContext ctx;
    private final PbbClient pbb;
    private final int me, n, t, fa;
    private final ECPoint G;
    private List<SharingOutput> Q1 = new ArrayList<>();
    private Map<Integer, ECPoint> Aij = new HashMap<>();
    private Map<Integer, BigInteger> aij = new HashMap<>();
    private ECPoint trueGroupKey = null;

    // 2) setter
    public void setTrueGroupKey(ECPoint trueGroupKey) {
        this.trueGroupKey = trueGroupKey;
    }

    public int getMe() {
        return me;
    }

    // 3) getter
    public ECPoint getTrueGroupKey() {
        return this.trueGroupKey;
    }

    public List<SharingOutput> getQ1() {
        // return a copy to avoid external mutation
        return Collections.unmodifiableList(Q1);
    }

    // Once per‐party: your reconstructed x_i & τ_pki
    // private BigInteger reconstructedShare;
    private ECPoint tauPki;
    private NizkDlEqProof thresholdProof;

    public VerificationPhase(PartyContext P) {
        this.P = P;
        this.ctx = P.ctx;
        this.pbb = P.pbb;
        this.me = P.id;
        this.n = P.n;
        this.t = P.t;
        this.fa = P.fa;
        this.G = ctx.getGenerator();
    }

    private boolean q1Finalized = false;

    public int q1Size() {
        return Q1.size();
    }

    public void finalizeQ1Deterministically() {
        if (q1Finalized)
            return;
        // Sort by dealer index for a stable, global order
        Q1.sort(Comparator.comparingInt(SharingOutput::getDealerIndex));
        int keep = Math.min(Q1.size(), t + fa);
        Q1 = new ArrayList<>(Q1.subList(0, keep));
        q1Finalized = true;
    }

    // Optional background snapshot source for "DealerPublish" (shared by all
    // instances)
    private static volatile TopicPoller<SharingOutputDTO> dealerPoller = null;

    public static void setDealerPoller(TopicPoller<SharingOutputDTO> p) {
        dealerPoller = p;
    }

    private List<SharingOutputDTO> dealerSnapshotOrFetch() throws Exception {
        TopicPoller<SharingOutputDTO> p = dealerPoller;
        if (p != null)
            return p.snapshot(); // non-blocking, in-memory snapshot
        return pbb.fetch("DealerPublish", SharingOutputDTO.class); // normal path
    }

    private void ensureAijForFinalQ1() {

        BigInteger sk = P.ephKey.getSecretKey();
        for (SharingOutput shj : Q1) {
            int j = shj.getDealerIndex();
            if (!Aij.containsKey(j)) {
                ECPoint Aji = shj.getCij()[me].subtract(shj.getDealerPub().multiply(sk)).normalize();
                if (Aji.isInfinity())
                    throw new IllegalStateException("INF A in τ recompute (dealer " + j + ")");
                BigInteger aji = shj.getCHat()[me];
                if (!G.multiply(aji).normalize().equals(Aji))
                    throw new IllegalStateException("A != G·a in τ recompute (dealer " + j + ")");
                Aij.put(j, Aji);
                aij.put(j, aji);
            }
        }
    }

    /**
     * Round 2 (Share Verification) Threshold Key Computation (optimistic).
     * 
     * @param dealerToVerify index for the dealer we are currently verifying.
     * @return the reconstructed Share S_i = (s, G^s)
     * @throws Exception
     * @throws IOException
     */

    private SharingOutput fetchAndCollectDealer(int dealerToVerify) throws IOException, Exception {
        SharingOutput so = null;
        while (so == null) {
            Thread.sleep(POLL_MS);
            for (SharingOutputDTO dto : dealerSnapshotOrFetch()) {
                if (dto.dealerIndexDTO != dealerToVerify)
                    continue;
                so = SharingOutput.fromDTO(dto, ctx);
                System.out.printf("✔ Collected Sh_%d%n", dealerToVerify);
                break;
            }
        }
        return so;
    }

    // ------------Share Verification (2nd round or after t fa parties post Shi
    // PBB.)----------------------------------------------------
    public void VerifySharesFor(int dealerToVerify) throws Exception {
        // Let Q₁ be the set of indices j such that Pⱼ are the first t+fₐ
        // parties to publish Sᵢⱼ on the PBB.
        // → here we spin until we see the dealer’s SharingOutput Sᵢ,*

        SharingOutput so = fetchAndCollectDealer(dealerToVerify);
        SharingOutput CurrentDealer = so;
        boolean samedealer = true;
        // quick sanity check
        if (CurrentDealer.dealerIndex == dealerToVerify) {
            samedealer = true;
        }

        System.out.println("is CurrentDealer == dealterToVerify??" + samedealer);

        List<PublicKeysWithProofs> pubs = DkgUtils.fetchAllEphemeralPubs(ctx, pbb, n);
        ECPoint[] E = new ECPoint[n];

        // Build an E-order index map
        java.util.Map<String, Integer> posByEnc = new java.util.HashMap<>();
        for (int k = 0; k < n; k++) {
            ECPoint Ek = pubs.get(k).getPublicKey().normalize();
            E[k] = Ek;
            // put it on the HashMap as a HexString.
            posByEnc.put(org.bouncycastle.util.encoders.Hex.toHexString(Ek.getEncoded(true)), k);
        }
        int posMe;

        String myEnc = org.bouncycastle.util.encoders.Hex
                .toHexString(P.ephKey.getPublic().normalize().getEncoded(true));
        Integer pm = posByEnc.get(myEnc);
        if (pm == null)
            throw new IllegalStateException("Can't find myself in E-list");
        posMe = pm;

        // 1) RE-DERIVE m*(x) using the correct dealerPub seed
        BigInteger[] mStar = HashingTools.deriveMStar(
                ctx,
                CurrentDealer.dealerPub, // <-- the key pkj from the dealer we want to verify
                E, // <-- pkk with proof from all dealer on the public list.
                CurrentDealer.Cij, // <-- the Cij of the dealer we want to verify
                CurrentDealer.CHat, // <-- the CHat of the dealer we want to verify
                n, t);

        System.out.println("Verifier computed mStar: " + Arrays.toString(mStar));

        log.info(mStar + "Is formed");

        // ---- 2) recompute (U,V) ----
        BigInteger p = ctx.getOrder();
        BigInteger[] alpha = ctx.getAlphas(); // convention: alpha[1..n] are valid, alpha[0] unused
        BigInteger[] lambda = ctx.getVs(); // v_k for k in [0..n-1]

        ECPoint U = G.getCurve().getInfinity();
        ECPoint V = G.getCurve().getInfinity();

        // Use a 0-based loop variable k for recipients; map to alpha[k+1]
        for (int k = 0; k < n; k++) {
            BigInteger f = EvaluationTools.evaluatePolynomial(mStar, alpha[k + 1], p);
            BigInteger w = lambda[k].multiply(f).mod(p);

            // E_k and C_{j,k} must be in party-index order [0..n-1]
            U = U.add(E[k].multiply(w)).normalize();
            V = V.add(CurrentDealer.Cij[k].multiply(w)).normalize();
        }

        // ---- 3) DLEQ ----
        if (!NizkDlEqProof.verifyProof(ctx, CurrentDealer.dealerPub, U, V, CurrentDealer.proof)) {
            log.info("dealer DLEQ failed {}", dealerToVerify);
            // remove dealer if DLEQ fails.
            for (int q = 0; q < Q1.size(); q++) {
                if (Q1.get(q).getDealerIndex() == dealerToVerify) {
                    Q1.remove(q);
                    break;
                }
            }
            // Skipping step 4, 5, 6
            return;
        }
        log.info("DLEQ SUCCESS for dealer {}", dealerToVerify);

        // add dealer once
        boolean alreadyInQ1 = false;
        for (int q = 0; q < Q1.size(); q++) {
            if (Q1.get(q).getDealerIndex() == dealerToVerify) {
                alreadyInQ1 = true;
                break;
            }
        }
        if (!alreadyInQ1)
            Q1.add(CurrentDealer);

        // ---- 4) decrypt & unmask ONLY your share for this dealer (i = me) ----
        BigInteger sk_i = P.ephKey.getSecretKey();

        ECPoint Ej = CurrentDealer.dealerPub; // E_j
        ECPoint Cji = CurrentDealer.Cij[posMe]; // C_{j,i}
        BigInteger chi = CurrentDealer.CHat[posMe]; // ĉ_{j,i}

        // A_{j,i} = C_{j,i} - sk_i * E_j
        ECPoint Aji = Cji.subtract(Ej.multiply(sk_i)).normalize();

        // a_{j,i} = ĉ_{j,i} XOR H(A_{j,i}) (byte-exact inside MaskedShareCHat)

        BigInteger aji = MaskedShareCHat.unmaskShare(Aji, chi, p);

        // ------5) Check that A'j,i <-- a'j,i * G and, if not, remove from Q1 (In
        // practice it should go to step 6, compute a DLEQ and publish complaint)
        if (!G.multiply(aji).normalize().equals(Aji)) {
            log.warn("Bad masked share for dealer {} (me={})", dealerToVerify, posMe);
            // dump minimal bytes to compare
            byte[] Aenc = Aji.getEncoded(true);
            byte[] H = java.security.MessageDigest.getInstance("SHA-256").digest(Aenc);
            byte[] chat = MaskedShareCHat.toFixed32(chi);
            log.debug("A={}", org.bouncycastle.util.encoders.Hex.toHexString(Aenc));
            log.debug("ĉ={}", org.bouncycastle.util.encoders.Hex.toHexString(chat));
            log.debug("H(A)={}", org.bouncycastle.util.encoders.Hex.toHexString(H));
            log.debug("a={}", aji.toString(16));
            log.debug("G·a={}",
                    org.bouncycastle.util.encoders.Hex.toHexString(G.multiply(aji).normalize().getEncoded(true)));
            // drop this dealer for me
            for (int q = 0; q < Q1.size(); q++)
                if (Q1.get(q).getDealerIndex() == dealerToVerify) {
                    Q1.remove(q);
                    break;
                }
            return;
        }
        // iff this check passes put Aji and aji on there hashmaps on the in the
        // VerificationPhase container.
        Aij.put(dealerToVerify, Aji);
        aij.put(dealerToVerify, aji);

        // Debug to check if there is an index problem and its of by one.
        int matchK = -1;
        for (int k = 0; k < n; k++) {
            BigInteger a_k = MaskedShareCHat.unmaskShare(Aji, CurrentDealer.CHat[k], ctx.getOrder());
            if (G.multiply(a_k).normalize().equals(Aji)) {
                matchK = k;
                break;
            }
        }
        if (matchK != -1 && matchK != posMe) {
            log.error("ĉ-index mismatch: me={}, but ĉ matches k={}", posMe, matchK);
        }

        // Now unmask with our own ĉ_{j,i

        log.info("A'j,i equals Cj,i - ski * Ej");

    }

    // Threshold Key Computation (Optimistic, as part of Share Verification)

    public void publishThresholdOutput() throws Exception {
        finalizeQ1Deterministically();
        if (Q1.isEmpty()) {
            log.error("Refusing to publish Θ_{}: Q1 is empty.", me);
            return;
        }

        // Build τ from fresh A_{j,i} computed from the SAME column C_{j,i} used for W_i
        ECPoint tau = G.getCurve().getInfinity();
        ECPoint Wi = G.getCurve().getInfinity();
        BigInteger sk_i = P.ephKey.getSecretKey();

        for (SharingOutput shj : Q1) {
            int j = shj.getDealerIndex();
            ECPoint Ej = shj.getDealerPub();
            ECPoint Cji = shj.getCij()[me]; // the column you use for W_i
            Wi = Wi.add(Cji).normalize();

            // ALWAYS recompute A_{j,i} from this C_{j,i} and E_j
            ECPoint AjiFresh = Cji.subtract(Ej.multiply(sk_i)).normalize();

            // (Optional sanity: per-dealer identity must hold)
            ECPoint chk = AjiFresh.add(Ej.multiply(sk_i)).normalize();
            if (!chk.equals(Cji)) {
                log.error("Per-dealer mismatch for dealer {}: A+skE != C (should never happen)", j);
            }

            // Use fresh A for τ and refresh the cache
            tau = tau.add(AjiFresh).normalize();
            Aij.put(j, AjiFresh);
        }
        this.tauPki = tau;

        // EQ1 := Σ_{j∈Q1} E_j (unambiguous)
        ECPoint EQ1 = G.getCurve().getInfinity();
        for (SharingOutput shj : Q1)
            EQ1 = EQ1.add(shj.getDealerPub()).normalize();

        // Publish Δ = s_i · EQ1 (canonical) and warn if local (W_i − τ) disagrees
        ECPoint deltaCanonical = EQ1.multiply(sk_i).normalize();
        ECPoint deltaLocal = Wi.subtract(tau).normalize();
        if (!deltaLocal.equals(deltaCanonical)) {
            log.warn("Δ mismatch: (W_i−τ) != s_i·EQ1 (likely a stale A_{j,i} cache or dealer-column mismatch). " +
                    "Publishing proof with Δ = s_i·EQ1.");
        }
        ECPoint delta = Wi.subtract(tau).normalize();
        boolean sane = EQ1.multiply(P.ephKey.getSecretKey()).normalize().equals(delta);
        log.debug("publish sanity: (Wi-τ)==s_i·EQ1 ? {}", sane);

        ECPoint Ei = P.ephKey.getPublic();
        this.thresholdProof = NizkDlEqProof.generateProof(ctx, Ei, EQ1, deltaCanonical, sk_i);
        boolean ok = NizkDlEqProof.verifyProof(ctx, Ei, EQ1, deltaCanonical, thresholdProof);
        log.info("   → DLEQ proof: e={}  z={}  verify={}",
                thresholdProof.getChallenge().toString(16),
                thresholdProof.getResponse().toString(16),
                ok);

        pbb.publish("ShareVerificationOutput",
                ShareVerificationOutputDTO.from(new ShareVerificationPublish(me, tauPki, thresholdProof)));
        log.info("→ DLEQ Θ_{}", me);
    }

    public List<ShareVerificationPublish> collectAndPruneThresholdOutputs() throws Exception {
        finalizeQ1Deterministically();
        ensureAijForFinalQ1(); // must be filled by VerifySharesFor()

        // Build E[0..n-1] by partyIndex (don’t rely on fetch order!)
        List<EphemeralKeyDTO> dtos = pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class);
        ECPoint[] E = new ECPoint[n];
        for (EphemeralKeyDTO dto : dtos) {
            ECPoint P = ctx.getGenerator().getCurve()
                    .decodePoint(org.bouncycastle.util.encoders.Hex.decode(dto.publicKey))
                    .normalize();
            E[dto.partyIndex] = P;
        }

        int needed = t + fa;
        java.util.Map<Integer, ShareVerificationPublish> received = new java.util.HashMap<>();
        while (received.size() < needed) {
            Thread.sleep(POLL_MS);
            for (ShareVerificationOutputDTO dto : pbb.fetch("ShareVerificationOutput",
                    ShareVerificationOutputDTO.class)) {
                int pi = dto.verifierIndex;
                if (!received.containsKey(pi)) {
                    ShareVerificationPublish out = ShareVerificationPublish.fromDTO(dto, P.ctx);
                    received.put(pi, out);
                    log.info("Collected Θ_{} ({}/{})", pi, received.size(), needed);
                    if (received.size() >= needed)
                        break;
                }
            }
        }
        List<ShareVerificationPublish> Q2 = new ArrayList<>(received.values());
        log.info("✅ Q2 formed ({} parties)", Q2.size());

        // EQ1 := Σ_{k∈Q1} E_k
        ECPoint EQ1 = ctx.getGenerator().getCurve().getInfinity();
        for (SharingOutput shj : Q1)
            EQ1 = EQ1.add(shj.getDealerPub()).normalize();

        // Prune invalid Θ_j. For each publisher j:
        // W_j := Σ_{k∈Q1} C_{k, slotOf(X_j)}
        // Δ_j := W_j − τ_{pk_j}
        // verify DLEQ(G, X_j ; EQ1, Δ_j)
        for (Iterator<ShareVerificationPublish> it = Q2.iterator(); it.hasNext();) {
            ShareVerificationPublish out = it.next();
            int j = out.verifierIndex;

            ECPoint Xj = E[j];
            if (Xj == null) { // missing key -> drop
                log.warn("Missing ephemeral pub for party {}, dropping from Q2", j);
                it.remove();
                continue;
            }

            // W_j = Σ_{k∈Q1} C_{k,j} (NOTE: column index == party index j)
            ECPoint Wj = ctx.getGenerator().getCurve().getInfinity();
            for (SharingOutput shk : Q1) {
                Wj = Wj.add(shk.getCij()[j]).normalize();
            }
            ECPoint deltaJ = Wj.subtract(out.tpki).normalize();

            boolean ok = NizkDlEqProof.verifyProof(ctx, Xj, EQ1, deltaJ, out.Pftpki);

            // Optional one-shot fallback: if your dealers actually used an E-order column,
            // try the slot of Xj in E before dropping.
            if (!ok) {
                int pos = -1;
                for (int s = 0; s < n; s++) {
                    if (E[s] != null && E[s].equals(Xj)) {
                        pos = s;
                        break;
                    }
                }
                if (pos >= 0 && pos != j) {
                    ECPoint Wj2 = ctx.getGenerator().getCurve().getInfinity();
                    for (SharingOutput shk : Q1)
                        Wj2 = Wj2.add(shk.getCij()[pos]).normalize();
                    ECPoint deltaJ2 = Wj2.subtract(out.tpki).normalize();
                    ok = NizkDlEqProof.verifyProof(ctx, Xj, EQ1, deltaJ2, out.Pftpki);
                }
            }

            if (!ok) {
                log.warn("↪ Threshold proof invalid for party {}, dropping from Q2", j);
                it.remove();
            } else {
                log.info("↪ Threshold proof OK for party {}", j);
            }
        }

        if (Q2.size() < t + 1) {
            throw new IllegalStateException("Not enough valid Θ for reconstruction: " + Q2.size());
        }
        return Q2;
    }

    public void finalReconstruction(List<SharingOutput> Q1, List<ShareVerificationPublish> Q2) throws Exception {
        // Build E by party index again
        List<EphemeralKeyDTO> dtos = pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class);
        ECPoint[] E = new ECPoint[n];
        for (EphemeralKeyDTO dto : dtos) {
            ECPoint P = ctx.getGenerator().getCurve()
                    .decodePoint(org.bouncycastle.util.encoders.Hex.decode(dto.publicKey))
                    .normalize();
            E[dto.partyIndex] = P;
        }
        // EQ1 := Σ_{k∈Q1} E_k
        ECPoint EQ1 = ctx.getGenerator().getCurve().getInfinity();
        for (SharingOutput shj : Q1)
            EQ1 = EQ1.add(shj.getDealerPub()).normalize();

        for (Iterator<ShareVerificationPublish> it = Q2.iterator(); it.hasNext();) {
            ShareVerificationPublish out = it.next();
            int j = out.verifierIndex;
            ECPoint Xj = E[j];
            if (Xj == null) {
                it.remove();
                continue;
            }

            ECPoint Wj = ctx.getGenerator().getCurve().getInfinity();
            for (SharingOutput sh : Q1)
                Wj = Wj.add(sh.getCij()[j]).normalize();
            ECPoint deltaJ = Wj.subtract(out.tpki).normalize();

            boolean ok = NizkDlEqProof.verifyProof(ctx, Xj, EQ1, deltaJ, out.Pftpki);
            if (!ok) {
                // Same optional fallback as above
                int pos = -1;
                for (int s = 0; s < n; s++) {
                    if (E[s] != null && E[s].equals(Xj)) {
                        pos = s;
                        break;
                    }
                }
                if (pos >= 0 && pos != j) {
                    ECPoint Wj2 = ctx.getGenerator().getCurve().getInfinity();
                    for (SharingOutput sh : Q1)
                        Wj2 = Wj2.add(sh.getCij()[pos]).normalize();
                    ECPoint deltaJ2 = Wj2.subtract(out.tpki).normalize();
                    ok = NizkDlEqProof.verifyProof(ctx, Xj, EQ1, deltaJ2, out.Pftpki);
                }
            }

            // ---- Step 7: Reconstruct the group public key G^x from τ_pk_j (j ∈ Q2) ----
            // Do NOT re-decrypt or re-unmask here; that was done in VerifySharesFor().
            // We only need τ_pk_j (out.tpki) and the evaluation points.

            if (!ok) {
                log.warn("↪ Threshold proof invalid for party {}, dropping from Q2", j);
                it.remove();
            } else {
                log.info("↪ Threshold proof OK for party {}", j);
            }
        }

        // Reconstruct G^x from the remaining τ_pk_j (unchanged)
        int m2 = Q2.size();
        Share[] tpkShares = new Share[m2];
        int[] tpkIdx = new int[m2];
        for (int k = 0; k < m2; k++) {
            int j = Q2.get(k).verifierIndex;
            tpkIdx[k] = j + 1; // if α_j = j+1
            tpkShares[k] = new Share(BigInteger.ZERO, Q2.get(k).tpki);
        }
        ECPoint Gx = GShamirShareDKG.ShamirSharingResult.reconstructSecretEC(ctx, tpkShares, tpkIdx);
        ECPoint gxNorm = Gx.normalize();

        ECPoint prev = DkgRef.TRUE_Y.compareAndExchange(null, gxNorm);
        if (prev == null) {
            // we stored the reference
            log.info("Stored trueGroupKey reference = {}",
                    org.bouncycastle.util.encoders.Hex.toHexString(gxNorm.getEncoded(true)));
        } else {
            // compare against the stored reference
            if (!prev.equals(gxNorm)) {
                log.warn("Group‐key mismatch! reconstructed {} but expected {}",
                        org.bouncycastle.util.encoders.Hex.toHexString(gxNorm.getEncoded(true)),
                        org.bouncycastle.util.encoders.Hex.toHexString(prev.getEncoded(true)));
            } else {
                log.info("✓ Group‐key matches reference.");
                log.info("🎉 reconstruction OK!");
            }
        }

    }
}
