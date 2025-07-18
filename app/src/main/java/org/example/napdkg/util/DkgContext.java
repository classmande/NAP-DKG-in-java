package org.example.napdkg.util;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Public parameters for YOSO‑style DHPVSS:
 *
 * pp = (𝔾, p, t, n, {α₀,…,αₙ}, {v₁,…,vₙ})
 *
 * where
 * • 𝔾 is the elliptic‐curve subgroup of prime order p (returned by
 * getGenerator())
 * • t is the threshold (degree of the sharing polynomial)
 * • n is the total number of participants
 * • α₀,…,αₙ ∈ ℤₚ are the distinct Shamir evaluation points (α₀ used to force
 * m(α₀)=0)
 * • vᵢ = ∏_{j≠i} (α₀−αⱼ)/(αᵢ−αⱼ) mod p are the SCRAPE dual‐code coefficients
 */
public class DkgContext {
    private final GroupGenerator.GroupParameters groupParams;
    private final int t; // threshold t
    private final int n; // number of participants n
    private final BigInteger[] alphas; // evaluation points α₀ … αₙ
    private final BigInteger[] v; // dual‐code weights v₁ … vₙ

    public DkgContext(
            GroupGenerator.GroupParameters groupParams,
            int t,
            int n,
            BigInteger[] alphas,
            BigInteger[] v) {
        this.groupParams = groupParams;
        this.t = t;
        this.n = n;
        this.alphas = alphas;
        this.v = v;

    }

    /**
     * @return p — the prime order of the EC subgroup (ℤₚ) used throughout NAP-DKG
     */
    public BigInteger getOrder() {
        return groupParams.getgroupOrd();
    }

    public BigInteger getCoFactor() {
        return groupParams.getCofactor();
    }

    /**
     * @return G — the generator of the elliptic‐curve subgroup 𝔾 of order p
     */
    public ECPoint getGenerator() {
        return groupParams.getG();
    }

    /** @return underlying EC group parameters (curve, generator, order, etc.) */
    public GroupGenerator.GroupParameters getGroupParameters() {
        return groupParams;
    }

    public ECCurve getCurve() {
        return groupParams.getCurve();
    }

    /** @return t — the threshold (degree of Shamir polynomial) */
    public int getThreshold() {
        return t;
    }

    /** @return n — the total number of participants */
    public int getNumParticipants() {
        return n;
    }

    /** @return {α₀,…,αₙ} — the Shamir evaluation points in ℤₚ */
    public BigInteger[] getAlphas() {
        return alphas;
    }

    /** @return {v₁,…,vₙ} — the SCRAPE dual‐code coefficients mod p */
    public BigInteger[] getVs() {
        return v;
    }

}
