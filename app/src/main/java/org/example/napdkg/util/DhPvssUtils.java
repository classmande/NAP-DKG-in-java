package org.example.napdkg.util;

import java.math.BigInteger;

/**
 * Utility routines for DHPVSS as in the YOLO‑YOSO paper.
 *
 * All finite‑field ops (e.g. SCRAPE dual‑code) are done over Zₚ,
 * where p is the order of the EC subgroup 𝔾 (generator G).
 *
 * In particular, for i∈[1..n] we compute the dual‑code (SCRAPE) weights
 * 
 * vᵢ = ∏_{j=1, j≠i}ⁿ (αᵢ − αⱼ)^(−1) mod p
 *
 * These vᵢ are used when aggregating shares for the consistency check.
 */
public class DhPvssUtils {
    /**
     * Simple SCRAPE dual‐code weights:
     *
     * v_j = ∏_{k=1, k≠j}^n (α[j] - α[k])^{-1} (mod p),
     * for j=1..n.
     *
     * @param p      prime modulus
     * @param alphas array of length (n+1), where alphas[0]=0 unused, and
     *               alphas[1..n] are distinct
     * @param n      total number of participants
     * @return BigInteger[n] = { v₁, v₂, …, vₙ } (zero‐based array)
     */
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

}
