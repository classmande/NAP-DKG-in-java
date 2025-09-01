package org.example.napdkg.util;

import java.math.BigInteger;

public class toyexample {
    public static void main(String[] args) {
        // Parameters
        BigInteger p = BigInteger.valueOf(23); // tiny for testing
        int n = 5, t = 2;
        BigInteger[] alpha = new BigInteger[n + 1];
        for (int i = 1; i <= n; i++)
            alpha[i] = BigInteger.valueOf(i);

        // Dealer secret and coefficients
        BigInteger secret = BigInteger.valueOf(3); // say, s = 3
        BigInteger[] coeffs = { secret, BigInteger.valueOf(4), BigInteger.valueOf(5) }; // e.g. m(x) = 3 + 4x + 5x^2

        // Evaluate shares
        BigInteger[] shares = new BigInteger[n + 1];
        for (int i = 1; i <= n; i++) {
            BigInteger x = alpha[i];
            // m(x) = 3 + 4x + 5x^2 mod 23
            shares[i] = coeffs[0].add(coeffs[1].multiply(x)).add(coeffs[2].multiply(x).multiply(x)).mod(p);
        }

        // Compute dual code coefficients
        BigInteger[] v = DkgUtils.deriveShrapeCoeffs(p, alpha, n);

        // SCRAPE check for degrees 0, 1, 2
        for (int deg = 0; deg <= n - t - 1; deg++) {
            BigInteger sum = BigInteger.ZERO;
            for (int i = 1; i <= n; i++) {
                BigInteger mprime = alpha[i].modPow(BigInteger.valueOf(deg), p);
                BigInteger term = v[i - 1].multiply(mprime).mod(p).multiply(shares[i]).mod(p);
                sum = sum.add(term).mod(p);
            }
            System.out.printf("deg=%d: sum=%s\n", deg, sum);
        }

    }

}
