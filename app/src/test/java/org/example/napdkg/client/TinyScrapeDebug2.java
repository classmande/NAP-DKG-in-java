package org.example.napdkg.client;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * TinyScrapeDebug2.java
 *
 * Drop this into your project (e.g. org/example/napdkg/util/).
 * It prints out every intermediate step of SCRAPE’s “dual‐code + commitment”
 * check,
 * including the raw A_{i,j} commitments and their exponents.
 *
 * HOW TO INTEGRATE:
 *
 * 1) After you generate all of your Shamir commitments A_{i,j}, store them in
 * an array
 * ECPoint[] Aijs = new ECPoint[n]; (see example below).
 *
 * 2) Also have your masked‐share array
 * ECPoint[] Cij = new ECPoint[n];
 *
 * 3) In runSharingAsDealer(…), *after* you compute
 * BigInteger[] mStar = HashingTools.deriveFirstRoundPoly(...);
 * insert one call to
 *
 * TinyScrapeDebug2.debugScrapeWithCommitments(
 * ctx.getOrder(), // the prime p = |G|
 * E, // E[0..n-1] = ephemeral public keys
 * Cij, // Cij[0..n-1] = E[j]^ski + Aij
 * Aijs, // Aijs[0..n-1] = G^{a_{i,j}}
 * mStar, // the polynomial coefficients
 * ctx.getAlphas(), // alphas[0..n], α[0]=0, α[1..n] distinct
 * sk_i // this dealer’s ephemeral secret
 * );
 *
 * 4) Re‐run your SmokeTest. You will see, in the console, for each j=1..n:
 *
 * ● α₍j₎, m*(α₍j₎), vⱼ, rⱼ
 * ● Eⱼ^{rⱼ}, A_{i,j}^{rⱼ}
 * ● partial sums: Σ_{k=1..j} E_k^{r_k}, Σ_{k=1..j} A_{i,k}^{r_k}
 * ● final aggregator check: (Σ E^{r})^{sᵢ} vs Σ A^{r}
 *
 * As soon as Σ_{k=1..n} A_{i,k}^{r_k} != ∞, you know exactly which j caused it.
 *
 * CURVE SETUP:
 * This example fetches secp256r1 (“prime256v1” in BouncyCastle). Replace
 * the short name if you use a different named curve.
 *
 * Dependencies: you must have bouncycastle on your classpath.
 */
public class TinyScrapeDebug2 {

    // -------------------------------------------------------------------------
    // 1) Replace with the exact same EC parameters you use in DKG.
    // In your code you do: CustomNamedCurves.getByName("secp256r1").
    // Here we grab the same curve via ECNamedCurveTable.getParameterSpec().
    // -------------------------------------------------------------------------
    private static final ECParameterSpec SPEC = ECNamedCurveTable.getParameterSpec("secp256r1");
    private static final ECDomainParameters DOM = new ECDomainParameters(
            SPEC.getCurve(),
            SPEC.getG(),
            SPEC.getN(),
            SPEC.getH());

    // Your group‐order p = |G|. In BouncyCastle’s ECParameterSpec,
    // getN() returns the order of the basepoint G. That is exactly “p” in Z_p.
    private static final BigInteger p = DOM.getN();

    // Generator G
    private static final ECPoint G = DOM.getG();

    // -------------------------------------------------------------------------

    /**
     * Compute the SCRAPE “dual‐code” weights v[1..n]:
     *
     * v_j = ∏_{k=1, k≠j}ⁿ (α[j] − α[k])^(−1) mod p
     *
     * @param primeMod the prime modulus p = |G|
     * @param alphas   array of length (n+1), with alphas[0]=0 and alphas[1..n]
     *                 distinct
     * @param n        number of participants / shares
     * @return an array v[0..n-1] where v[j-1] = v_j
     */
    public static BigInteger[] deriveScrapeCoeffs(
            BigInteger primeMod,
            BigInteger[] alphas,
            int n) {
        BigInteger[] v = new BigInteger[n];
        for (int j = 1; j <= n; j++) {
            BigInteger prod = BigInteger.ONE;
            for (int k = 1; k <= n; k++) {
                if (j == k)
                    continue;
                BigInteger diff = alphas[j].subtract(alphas[k]).mod(primeMod);
                BigInteger inv = diff.modInverse(primeMod);
                prod = prod.multiply(inv).mod(primeMod);
            }
            v[j - 1] = prod;
        }
        return v;
    }

    /**
     * Horner‐evaluate polynomial c[0..d] at x=alpha (mod primeMod):
     * result = c[0] + c[1]·alpha + c[2]·alpha^2 + ... (mod primeMod).
     */
    public static BigInteger evaluatePolynomial(
            BigInteger[] coeffs,
            BigInteger alpha,
            BigInteger primeMod) {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPow = BigInteger.ONE; // alpha^0 = 1
        for (BigInteger coef : coeffs) {
            result = result.add(coef.multiply(xPow)).mod(primeMod);
            xPow = xPow.multiply(alpha).mod(primeMod);
        }
        return result;
    }

    /**
     * VERY VERBOSE SCRAPE DEBUG:
     *
     * (a) Print v[1..n], m*(α_j), r_j = v_j·m*(α_j) mod p, and ∑ r_j mod p.
     * (b) For each j, print E[j]^{r_j} and Aijs[j]^{r_j}, then partial sums.
     * (c) Finally check that (Σ_j E[j]^{r_j})^{s_i} == Σ_j A_{i,j}^{r_j}.
     *
     * @param primeMod the prime modulus p = |G|
     * @param E        E[0..n-1] = ephemeral public keys E_j for each party j
     * @param Cij      Cij[0..n-1] = “masked shares” E_j^{s_i} + Aij
     * @param Aijs     Aijs[0..n-1] = the raw Shamir commitments G^{a_{i,j}}
     * @param mStar    polynomial coefficients [c_0 … c_t] from HashingTools
     * @param alphas   array length (n+1), alphas[0]=0, alphas[1..n] distinct
     * @param sk_i     this dealer’s ephemeral secret
     */
    public static void debugScrapeWithCommitments(
            BigInteger primeMod,
            ECPoint[] E,
            ECPoint[] Cij,
            ECPoint[] Aijs,
            BigInteger[] mStar,
            BigInteger[] alphas,
            BigInteger sk_i) {
        int n = E.length;
        System.out.println("\n==== TINY SCRAPE DEBUG BEGIN ====");

        // 1) Compute v[1..n]
        BigInteger[] vArr = deriveScrapeCoeffs(primeMod, alphas, n);
        System.out.println("  ➜ SCRAPE weights v[] = " + Arrays.toString(vArr));

        // 2) Evaluate m*(α_j), compute r_j = v_j·m*(α_j) mod p, sum up r
        BigInteger sumR = BigInteger.ZERO;
        System.out.println("  ➜ Polynomial m*(x) coefficients = " + Arrays.toString(mStar));
        for (int j = 1; j <= n; j++) {
            BigInteger alpha_j = alphas[j];
            BigInteger eval = evaluatePolynomial(mStar, alpha_j, primeMod);
            BigInteger rj = vArr[j - 1].multiply(eval).mod(primeMod);
            sumR = sumR.add(rj).mod(primeMod);

            System.out.printf(
                    "    j=%d:  α₍%d₎ = %s%n      → m*(α) = %s%n      → v[%d] = %s%n      → r[%d] = %s%n",
                    j, j, alpha_j.toString(16),
                    eval.toString(16),
                    j, vArr[j - 1].toString(16),
                    j, rj.toString(16));
        }
        System.out.println("  ➜ ∑_{j=1..n} r[j] mod p = " + sumR.toString(16)
                + "   (should be 0)");

        // 3) Build U and “commitment‐sum” W = Σ A_{i,j}^{r_j}, printing partial sums
        ECPoint U = DOM.getCurve().getInfinity();
        ECPoint W = DOM.getCurve().getInfinity();
        System.out.println("\n  ➜ Now building U = Σ E[j]^{r_j}  and  W = Σ A_{i,j]^{r_j} :");
        for (int j = 1; j <= n; j++) {
            BigInteger rj = vArr[j - 1].multiply(
                    evaluatePolynomial(mStar, alphas[j], primeMod)).mod(primeMod);

            // E[j−1]^{r_j}
            ECPoint partialU = E[j - 1].multiply(rj).normalize();

            // Aijs[j−1]^{r_j}
            ECPoint partialW = Aijs[j - 1].multiply(rj).normalize();

            // Cij[j−1]^{r_j} = (E[j]^{s_i} + A_{i,j})^{r_j} = E[j]^{s_i·r_j} +
            // A_{i,j}^{r_j}
            // We will check separately by comparing U^{s_i} vs (Σ A^{r})

            System.out.printf(
                    "    j=%d:  r[%d] = %s%n      E[%d]^{r} = %s%n      Aij[%d]^{r} = %s%n",
                    j, j, rj.toString(16),
                    j, partialU,
                    j, partialW);

            // Accumulate
            U = U.add(partialU).normalize();
            W = W.add(partialW).normalize();

            System.out.printf(
                    "      → partial U = %s%n      → partial W = %s%n",
                    U, W);
        }

        // 4) Final check: (Σ E^{r})^{s_i} ?= Σ A^{r}
        ECPoint check = U.multiply(sk_i).normalize();
        System.out.println("\n  ➜ Final aggregator U = " + U);
        System.out.println("  ➜ Final commitment‐sum W = " + W);
        System.out.println("  ➜ (U)^{s_i} = " + check);

        if (check.equals(W)) {
            System.out.println("  ✅  U^{s_i} == W  → SCRAPE consistency holds!");
        } else {
            System.out.println("  ⛔  U^{s_i} != W  → SCRAPE failed (mismatch)!");
        }
        System.out.println("==== TINY SCRAPE DEBUG END ====\n");
    }

    /**
     * A tiny “toy‐field” unit test you can run right here.
     * This does n=3, p=23, α={1,2,3}, m*(x)=7+3·x and confirms v=[12,22,12],
     * r=[5,10,8], Σr=0.
     */
    public static void main(String[] args) {
        BigInteger toyP = BigInteger.valueOf(23);
        BigInteger[] toyAlphas = new BigInteger[] {
                BigInteger.ZERO,
                BigInteger.ONE,
                BigInteger.valueOf(2),
                BigInteger.valueOf(3)
        };
        BigInteger[] toyPoly = new BigInteger[] {
                BigInteger.valueOf(7), // constant term
                BigInteger.valueOf(3) // x‐coefficient
        };
        int n = 3;

        BigInteger[] vArr = deriveScrapeCoeffs(toyP, toyAlphas, n);
        System.out.println("Toy dual‐code weights v = " + Arrays.toString(vArr));
        BigInteger sumR = BigInteger.ZERO;
        for (int j = 1; j <= n; j++) {
            BigInteger mval = evaluatePolynomial(toyPoly, toyAlphas[j], toyP);
            BigInteger rj = vArr[j - 1].multiply(mval).mod(toyP);
            System.out.printf(
                    "  j=%d: m*(%d)=%d, v=%d, r=%d%n",
                    j,
                    toyAlphas[j].intValue(),
                    mval.intValue(),
                    vArr[j - 1].intValue(),
                    rj.intValue());
            sumR = sumR.add(rj).mod(toyP);
        }
        System.out.println("Toy ∑r mod p = " + sumR + "  (should be 0)");
    }
}
