package org.example.napdkg.util;

import java.math.BigInteger;

/**
 * DHPVSS evaluation utilities in the YOLO YOSO model.
 * All arithmetic is done in the prime field ℤp (the subgroup order of the EC
 * group).
 */
public class EvaluationTools {

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
