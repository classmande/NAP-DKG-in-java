package org.example.napdkg.client;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

/**
 * SingleChallengeDKGTest:
 *
 * Demonstrates a "realistic" single-challenge aggregator check for a threshold
 * polynomial:
 * 1) n=5, t=2 (you can change as you wish).
 * 2) We generate ephemeral keys randomly for each party j: E[j] = G^sk_j.
 * 3) "Dealer" i has ephemeral secret sk_i, builds masked shares C[j] =
 * E[j]^sk_i + G^a_j
 * 4) We pick a single random challenge c in [1..p-1].
 * 5) aggregator sums:
 * U = sum_{j=1..n} c * E[j]
 * V = sum_{j=1..n} c * C[j]
 * 6) check that V == U^sk_i
 * 
 * In practice, this yields a non-zero aggregator sum ~99.9999% of the time
 * (no forced "sum=0" from Lagrange weighting).
 */
public class SingleChallengeDKGTest {

    // The secp256k1 group order "r". For other curves, replace with that curve's
    // subgroup order.
    private static final String pHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    public static void main(String[] args) {
        try {
            int n = 5;
            int t = 2;
            BigInteger p = new BigInteger(pHex, 16); // group order for exponents
            SecureRandom rnd = new SecureRandom();

            System.out.println("=== Single-Challenge DKG Demo with n=" + n + ", t=" + t + " ===");

            // 1) Dealer picks ephemeral secret sk_i, ephemeral pub pk_i = G^sk_i
            // We'll also pick the generator G from BouncyCastle's secp256k1
            // or any valid library. Here we do a minimal approach.
            // For the sake of demonstration, let's do a small "mock" G.
            // In real code, you want to retrieve EC parameters from a real library.

            // For brevity: let's define a minimal "Curve" in code. Or assume you have it:
            ECCurveSecp256k1 curve = new ECCurveSecp256k1(); // example code below
            ECPoint G = curve.getG();

            BigInteger sk_i = new BigInteger(p.bitLength(), rnd).mod(p);
            ECPoint pk_i = G.multiply(sk_i).normalize();
            System.out.println("Dealer ephemeral secret sk_i = " + sk_i.toString(16));
            System.out.println("Dealer ephemeral public pk_i = " + pk_i);

            // 2) Build a polynomial of degree <= t=2. a0 = s, plus random a1, a2
            // The "secret" is a0 = s
            BigInteger a0 = new BigInteger(p.bitLength(), rnd).mod(p);
            BigInteger a1 = new BigInteger(p.bitLength(), rnd).mod(p);
            BigInteger a2 = new BigInteger(p.bitLength(), rnd).mod(p);
            BigInteger[] poly = new BigInteger[] { a0, a1, a2 };
            System.out.println(
                    "Polynomial: a0=" + a0.toString(16) + "  a1=" + a1.toString(16) + "  a2=" + a2.toString(16));

            // 3) Evaluate shares for j=1..n:
            BigInteger[] shareVals = new BigInteger[n];
            ECPoint[] sharePoints = new ECPoint[n];
            for (int j = 1; j <= n; j++) {
                BigInteger sVal = evalPoly(poly, BigInteger.valueOf(j), p);
                shareVals[j - 1] = sVal;
                sharePoints[j - 1] = G.multiply(sVal).normalize();
                System.out.println("  share j=" + j + " => a_j=" + sVal.toString(16) + "  A_j=" + sharePoints[j - 1]);
            }

            // 4) Generate ephemeral keys for each party j: E[j] = G^sk_j
            List<BigInteger> secrets = new ArrayList<>();
            ECPoint[] E = new ECPoint[n];
            for (int j = 0; j < n; j++) {
                BigInteger sk_j = new BigInteger(p.bitLength(), rnd).mod(p);
                secrets.add(sk_j);
                E[j] = G.multiply(sk_j).normalize();
                System.out.println("Party j=" + j + ": ephemeral sk_j=" + sk_j.toString(16)
                        + " => E[j]=" + E[j]);
            }

            // 5) Build masked shares: C[j] = E[j]^sk_i + G^a_j
            // (the "dealer" i uses ephemeral exponent sk_i to mask)
            ECPoint[] C = new ECPoint[n];
            for (int j = 0; j < n; j++) {
                C[j] = E[j].multiply(sk_i).add(sharePoints[j]).normalize();
                System.out.println("C[" + j + "] = E[" + j + "]^sk_i + A_j = " + C[j]);
            }

            // 6) Single random challenge c in [1..p-1]:
            BigInteger c = new BigInteger(p.bitLength(), rnd).mod(p);
            if (c.equals(BigInteger.ZERO)) { // just in case
                c = c.add(BigInteger.ONE);
            }
            System.out.println("Aggregator single-challenge c = " + c.toString(16));

            // 7) aggregator sums:
            // U = sum_j c * E[j]
            // V = sum_j c * C[j]
            // Then checks if V == U^sk_i
            ECPoint U = curve.getInfinity();
            ECPoint V = curve.getInfinity();
            for (int j = 0; j < n; j++) {
                // factor = c
                ECPoint addU = E[j].multiply(c).normalize();
                ECPoint addV = C[j].multiply(c).normalize();
                U = U.add(addU).normalize();
                V = V.add(addV).normalize();
            }
            System.out.println("\nFinal aggregator U = " + U);
            System.out.println("Final aggregator V = " + V);

            ECPoint check = U.multiply(sk_i).normalize();
            if (check.equals(V)) {
                System.out.println("✔ Aggregator check PASSED:  V == U^sk_i");
            } else {
                System.out.println("✘ Aggregator check FAILED:  V != U^sk_i");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /** Evaluate polynomial at x (mod p) in standard Horner's method. */
    private static BigInteger evalPoly(BigInteger[] coeffs, BigInteger x, BigInteger p) {
        // coeffs[0] + coeffs[1]*x + coeffs[2]*x^2
        // or more generally, Horner:
        BigInteger result = BigInteger.ZERO;
        for (int i = coeffs.length - 1; i >= 0; i--) {
            result = result.multiply(x).add(coeffs[i]).mod(p);
        }
        return result;
    }

    // ---------------------------------------------------------------------
    // Minimal mocking of "secp256k1 curve" for demonstration
    // In real code, you would get the curve from BouncyCastle or similar, e.g.:
    // ECNamedCurveParameterSpec spec =
    // ECNamedCurveTable.getParameterSpec("secp256k1");
    // ECDomainParameters domain = new ECDomainParameters(spec.getCurve(),
    // spec.getG(), spec.getN(), spec.getH());
    // ...
    // For brevity, we do a trivial reference here:
    // ---------------------------------------------------------------------
    private static class ECCurveSecp256k1 {
        // Hardcoded secp256k1
        // Q: prime field of x,y. R: group order. G: base point
        // For real usage, use BC library or same.

        // The secp256k1 "G" in hex uncompressed is:
        // "04"
        // + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" (x)
        // + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8" (y)

        // We'll parse that into a BouncyCastle curve, or store a pre-coded ECPoint.
        private final org.bouncycastle.math.ec.custom.sec.SecP256K1Curve bcCurve;
        private final ECPoint G;

        ECCurveSecp256k1() {
            bcCurve = new org.bouncycastle.math.ec.custom.sec.SecP256K1Curve();
            // Typically, "bcCurve" plus "domain" etc. But let's do a direct decode:
            byte[] Gencoded = Hex.decode(
                    "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
                            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
            G = bcCurve.decodePoint(Gencoded).normalize();
        }

        public ECPoint getG() {
            return G;
        }

        public ECPoint getInfinity() {
            return bcCurve.getInfinity();
        }
    }
}
