package org.example.napdkg.core;

import java.math.BigInteger;

import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.DkgUtils;
import org.example.napdkg.util.GroupGenerator;

// Important!! Hard to understand - the derivation of the SCRAPE coefficients. Alert on mod-inversen and Reed-Solomon codes how they work! //
/**
 * DHPVSS_Setup initializes all public parameters for the YOSO‐style DHPVSS:
 *
 * – p : prime modulus (the order of the EC subgroup)
 * – G : curve generator (in group 𝔾 of order p)
 * – n, t : number of participants and threshold
 * – {α₀…αₙ} : distinct evaluation points in ℤₚ (with α₀ used in Shamir as the
 * “dealer point”)
 * – {v₁…vₙ} : SCRAPE dual‐code coefficients, where
 * vᵢ = ∏_{j∈[1..n], j≠i} (α₀ − αⱼ)/(αᵢ − αⱼ) mod p
 *
 * These are exactly the parameters needed for:
 * • Shamir shares: S + m(αᵢ)·G
 * • SCRAPE integrity checks via ∑ᵢ vᵢ·m*(αᵢ)=0
 * • SCRAPE aggregation U = ∑ᵢ vᵢ·Eᵢ, V = ∑ᵢ vᵢ·Cᵢ etc.
 */
public class DHPVSS_Setup {

    public static DkgContext dhPvssSetup(
            GroupGenerator.GroupParameters groupParams,
            int t, // threshold (degree of Shamir poly)
            int n) { // total participants

        // 1) Extract subgroup order p = |𝔾|
        BigInteger p = groupParams.getgroupOrd();
        if (p == null)
            throw new IllegalArgumentException("Missing curve order");
        if (n - t - 2 <= 0)
            // Check for debugging - realised that the order had to be at max n - t - 2 and
            // not n - t - 1.
            throw new IllegalArgumentException("Requires n − t − 2 > 0");

        // 2) Choose distinct evaluation points α₀ … αₙ ∈ ℤₚ
        // Here we simply set αᵢ = i for i = 0..n (in practice pick any distinct
        // nonzero)
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }

        // 4) Compute dual‐code weights v₁ … vₙ:
        // vᵢ = ∏_{j≠i} (α₀ − αⱼ)/(αᵢ − αⱼ) mod p
        BigInteger[] vs = DkgUtils.deriveShrapeCoeffs(
                groupParams.getgroupOrd(),
                alphas, // end index
                n);

        // 5) Package everything into the context:
        return new DkgContext(
                groupParams, // contains G and p
                t, // threshold
                n, // total parties
                alphas, // {α₀…αₙ}
                vs);
    }
}
