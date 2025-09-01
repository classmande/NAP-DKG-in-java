package org.example.napdkg.client;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.example.napdkg.core.DHPVSS_Setup;
import org.example.napdkg.core.GShamirShareDKG;
import org.example.napdkg.core.Share;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.DkgUtils;
import org.example.napdkg.util.GroupGenerator;
import org.example.napdkg.util.GroupGenerator.GroupParameters;

public class ScrapeDualCodeCheck {
    public static void main(String[] args) {
        // Set degree and coefficients explicitly
        int n = 10, t = 5;
        BigInteger p = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 1; i <= n; i++)
            alphas[i] = BigInteger.valueOf(i);
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        // 2) Build the DkgContext with n=3, t=1
        DkgContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        // Test with a constant polynomial (should pass all degrees)
        // BigInteger[] coeffs = new BigInteger[t + 1];
        // coeffs[0] = BigInteger.ONE;
        // for (int j = 1; j <= t; j++)
        // coeffs[j] = BigInteger.ZERO;
        // BigInteger[] shares = new BigInteger[n];
        // for (int i = 1; i <= n; i++)
        // shares[i - 1] = coeffs[0];
        SecureRandom rnd = new SecureRandom();
        BigInteger s = new BigInteger(p.bitLength(), rnd).mod(p);

        // Shamir-share “s” among n parties
        GShamirShareDKG.ShamirSharingResult res = GShamirShareDKG.ShamirSharingResult.generateShares(ctx, s);
        Share[] shares = res.shares;

        // Now do the SCRAPE check as in your test
        BigInteger[] v = DkgUtils.deriveShrapeCoeffs(p, alphas, n);
        for (int degree = 0; degree <= n - t - 1; degree++) {
            BigInteger sum = BigInteger.ZERO;
            for (int i = 1; i <= n; i++) {
                BigInteger mPrimeEval = alphas[i].modPow(BigInteger.valueOf(degree), p);
                BigInteger term = v[i - 1].multiply(mPrimeEval).mod(p)
                        .multiply(shares[i - 1].getai()).mod(p);
                sum = sum.add(term).mod(p);
            }
            System.out.println("deg=" + degree + ": sum=" + sum);

            if (!sum.equals(BigInteger.ZERO)) {
                System.out.println("❌ SCRAPE test FAILED for degree " + degree);
            } else {
                System.out.println("✔️ SCRAPE test PASSED for degree " + degree);
            }
        }

    }

    public static BigInteger evaluatePolynomial(BigInteger[] coeffs, BigInteger x, BigInteger p) {
        BigInteger result = coeffs[coeffs.length - 1];
        for (int i = coeffs.length - 2; i >= 0; i--) {
            result = result.multiply(x).add(coeffs[i]).mod(p);
        }
        return result;
    }
}