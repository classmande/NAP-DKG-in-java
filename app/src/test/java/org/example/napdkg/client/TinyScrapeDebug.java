package org.example.napdkg.client;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve; // example curve; replace with yours

/**
 * TinySCRAPE Debug Helper
 *
 * Drop this class into your project, adjust the curve parameters (G, p, etc.),
 * then call debugScrape(...) from your SharingPhase to print everything.
 */
public class TinyScrapeDebug {

    // -------------------------------
    // 1) Replace with your actual EC curve + generator (G) + group‐order (p)
    // Below is just an example using secp256k1 from BouncyCastle;
    // your real code will use ctx.getGenerator(), ctx.getOrder(), etc.
    // -------------------------------
    private static final ECCurve CURVE = new SecP256K1Curve();
    private static final ECFieldElement Xcoord = new SecP256K1Curve().fromBigInteger(
            new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16));
    private static final ECFieldElement Ycoord = new SecP256K1Curve().fromBigInteger(
            new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16));
    private static final ECPoint G = CURVE.createPoint(Xcoord.toBigInteger(), Ycoord.toBigInteger());
    // For demonstration purposes only: use the curve‐order from secp256k1
    private static final BigInteger p = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    // -------------------------------
    // 2) Simple SCRAPE‐dual‐code weight computation:
    // v_j = ∏_{k≠j} (α[j] - α[k])^{-1} mod p
    // -------------------------------
    public static BigInteger[] deriveShrapeCoeffs(
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

    // -------------------------------
    // 3) Horner‐evaluate a polynomial c[0..d] at X = alpha, mod primeMod
    // -------------------------------
    public static BigInteger evaluatePolynomial(
            BigInteger[] coeffs,
            BigInteger alpha,
            BigInteger primeMod) {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPow = BigInteger.ONE; // starts at α^0
        for (BigInteger coef : coeffs) {
            result = result.add(coef.multiply(xPow)).mod(primeMod);
            xPow = xPow.multiply(alpha).mod(primeMod);
        }
        return result;
    }

    // -------------------------------
    // 4) Main debug function: prints v_j, m*(α_j), r_j, partialU/partialV, sum(r)
    // - E[] and Cij[] must come from your SharingPhase
    // - sk_i is the dealer’s ephemeral secret
    // - mStar is the derived polynomial [c0,c1,...]
    // - alphas is length (n+1), with alphas[0]=0, alphas[1..n] distinct nonzero
    // -------------------------------
    public static void debugScrape(
            BigInteger primeMod,
            ECPoint[] E, // E[0..n-1] = public keys E_j = G^sk_j
            ECPoint[] Cij, // Cij[0..n-1] = masked shares: = E[j]^ski + Aij
            BigInteger[] mStar, // polynomial coefficients [c0..ct], deg ≤ t
            BigInteger[] alphas, // [0..n], using only alphas[1..n]
            BigInteger sk_i // this dealer’s ephemeral secret
    ) {
        int n = E.length;
        System.out.println("\n==== TINY SCRAPE DEBUG BEGIN ====");
        // Step A: compute v[]
        BigInteger[] vArr = deriveShrapeCoeffs(primeMod, alphas, n);
        System.out.println("  ➜ SCRAPE weights v[] = " + Arrays.toString(vArr));

        // Step B: evaluate mStar at each α[j], then multiply by v[j] to get r[j]
        BigInteger[] rArr = new BigInteger[n];
        BigInteger sumR = BigInteger.ZERO;
        System.out.println("  ➜ Polynomial m*(x) coeffs = " + Arrays.toString(mStar));
        for (int j = 1; j <= n; j++) {
            BigInteger alpha_j = alphas[j];
            BigInteger eval = evaluatePolynomial(mStar, alpha_j, primeMod);
            rArr[j - 1] = vArr[j - 1].multiply(eval).mod(primeMod);
            sumR = sumR.add(rArr[j - 1]).mod(primeMod);

            System.out.printf(
                    "    j=%d: α₍%d₎=%s,  m*(α)=%s,  v=%s,  r=v·m%%p=%s%n",
                    j, j,
                    alpha_j.toString(16),
                    eval.toString(16),
                    vArr[j - 1].toString(16),
                    rArr[j - 1].toString(16));
        }
        System.out.println("  ➜ ∑_{j=1..n} r[j] mod p = " + sumR.toString(16)
                + "  (should be 0)");

        // Step C: build U and V, printing partial sums
        ECPoint U = CURVE.getInfinity();
        ECPoint V = CURVE.getInfinity();
        System.out.println("\n  ➜ Now building U = ∑ E[j]^r[j],  V = ∑ Cij[j]^r[j] :");
        for (int j = 1; j <= n; j++) {
            BigInteger rj = rArr[j - 1];
            ECPoint partialU = E[j - 1].multiply(rj).normalize();
            ECPoint partialV = Cij[j - 1].multiply(rj).normalize();

            System.out.printf(
                    "    j=%d:  r[%d]=%s%n      E[%d]^r = %s%n      Cij[%d]^r = %s%n",
                    j, j, rj.toString(16),
                    j, partialU, // toString on ECPoint prints (x,y)
                    j, partialV);
            U = U.add(partialU).normalize();
            V = V.add(partialV).normalize();
            System.out.printf(
                    "      → partial U = %s%n      → partial V = %s%n",
                    U, V);
        }

        // Step D: final check U^ski versus V
        ECPoint check = U.multiply(sk_i).normalize();
        System.out.println("\n  ➜ Final aggregator U = " + U);
        System.out.println("  ➜ Final aggregator V = " + V);
        System.out.println("  ➜ Check U^ski = " + check);
        if (check.equals(V)) {
            System.out.println("  ✅  U^ski == V  → SCRAPE consistency holds!");
        } else {
            System.out.println("  ⛔  U^ski != V  → SCRAPE failed (mismatch)!");
        }
        System.out.println("==== TINY SCRAPE DEBUG END ====\n");
    }

    // -------------------------------
    // 5) If you want to run a “toy prime‐field test” here in main(), do it:
    // Example: n=3, p=23, α={1,2,3}, v should be [12,22,12], etc.
    // -------------------------------
    public static void main(String[] args) {
        // Toy example: n=3, prime p=23, α={1,2,3}, m*(x)=7+3x
        BigInteger toyP = BigInteger.valueOf(23);
        BigInteger[] toyAlphas = new BigInteger[] {
                BigInteger.ZERO,
                BigInteger.ONE,
                BigInteger.valueOf(2),
                BigInteger.valueOf(3)
        };
        BigInteger[] toyPoly = new BigInteger[] {
                BigInteger.valueOf(7), // c0
                BigInteger.valueOf(3) // c1 → m*(x)=7 + 3x
        };
        int n = 3;

        // compute v[] and r[] and print
        BigInteger[] vArr = deriveShrapeCoeffs(toyP, toyAlphas, n);
        System.out.println("Toy v = " + Arrays.toString(vArr));
        BigInteger sumR = BigInteger.ZERO;
        for (int j = 1; j <= n; j++) {
            BigInteger mval = evaluatePolynomial(toyPoly, toyAlphas[j], toyP);
            BigInteger rj = vArr[j - 1].multiply(mval).mod(toyP);
            System.out.printf(" j=%d: m*(%d)=%d,  v=%d,  r=%d%n",
                    j,
                    toyAlphas[j].intValue(),
                    mval.intValue(),
                    vArr[j - 1].intValue(),
                    rj.intValue());
            sumR = sumR.add(rj).mod(toyP);
        }
        System.out.println("Sum r mod p = " + sumR + "  (should be 0)");
    }
}
