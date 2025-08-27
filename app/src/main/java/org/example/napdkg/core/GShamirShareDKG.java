package org.example.napdkg.core;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.util.DkgContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GShamirShareDKG {

    // Container for the result (the shares) from the GShamir.Share, holding the
    // Share[] with a Biginter for a and ECPoint for A.
    //
    public static class ShamirSharingResult {
        private static final Logger log = LoggerFactory.getLogger(GShamirShareDKG.class);
        public final Share[] shares;
        public final BigInteger[] coeffs;

        public ShamirSharingResult(Share[] shares, BigInteger[] coeffs) {
            this.shares = shares;
            this.coeffs = coeffs;
        }

        /**
         * Generates t-degree Shamir shares (a_i) at the points alpha[1..n],
         * together with the EC points A_i = G * a_i.
         *
         * @param ctx    the DHPVSS/DKG context (contains n, t, p, G, alphas[])
         * @param secret the dealer’s secret s ∈ Z_p
         * @return an array of Share objects of length n
         */
        public static ShamirSharingResult generateShares(DkgContext ctx, BigInteger secret) {
            int n = ctx.getNumParticipants(); // total # of shares
            int t = ctx.getThreshold(); // polynomial degree
            BigInteger p = ctx.getOrder(); // group order
            ECPoint G = ctx.getGenerator(); // group generator
            BigInteger[] alpha = ctx.getAlphas(); // alpha[0..n], with alpha[0]=0

            // 1) Sample random polynomial m(x) of degree ≤ t, with m(0)=secret
            BigInteger[] coeffs = new BigInteger[t + 1];
            SecureRandom rnd = new SecureRandom();
            coeffs[0] = secret.mod(p);
            for (int j = 1; j <= t; j++) {
                // uniform in [0, p)
                coeffs[j] = new BigInteger(p.bitLength(), rnd).mod(p);
            }

            // 2) Evaluate m at alpha[1..n], build shares
            Share[] out = new Share[n];
            for (int i = 1; i <= n; i++) {
                BigInteger x = alpha[i];
                // Horner’s method for polynomial evaluation

                BigInteger a_i = coeffs[t];
                for (int j = t - 1; j >= 0; j--) {
                    a_i = a_i.multiply(x).add(coeffs[j]).mod(p);

                }

                ECPoint A_i = G.multiply(a_i).normalize();
                out[i - 1] = new Share(a_i, A_i);
            }

            return new ShamirSharingResult(out, coeffs); //

        }

        public BigInteger[] getCoefficients() {
            return this.coeffs;
        }

        /**
         * Reconstructs the dealer’s secret scalar s = m(α₀) via Lagrange interpolation
         * at α₀, from t+1 Shamir shares a_i = m(α_i).
         *
         * @param ctx     the DHPVSS/DKG context (must hold p, alphas[] exactly as in
         *                generate())
         * @param shares  the Share[] array for the same indices
         * @param indices the matching 1‐based indices i ∈ I, |I| = t+1
         * @return the reconstructed secret s ∈ Zₚ
         */
        public static BigInteger reconstructSecretScalar(DkgContext ctx,
                Share[] shares,
                int[] indices) {
            if (shares.length != indices.length) {
                throw new IllegalArgumentException("share count ≠ indices count");
            }
            BigInteger p = ctx.getOrder();
            BigInteger[] alphas = ctx.getAlphas(); // [α₀, α₁, …, αₙ]
            BigInteger x0 = alphas[0]; // interpolate at α₀ so m(α₀)=s
            BigInteger sRec = BigInteger.ZERO;

            for (int k = 0; k < shares.length; k++) {
                int i = indices[k];
                BigInteger ai = shares[k].getai();
                BigInteger lambda = BigInteger.ONE;

                // ℓᵢ = ∏_{j≠i}(α₀−αⱼ)/(αᵢ−αⱼ) mod p
                for (int m = 0; m < shares.length; m++) {
                    if (m == k)
                        continue;
                    int j = indices[m];
                    BigInteger num = x0.subtract(alphas[j]).mod(p);
                    BigInteger den = alphas[i].subtract(alphas[j]).mod(p);
                    lambda = lambda
                            .multiply(num)
                            .multiply(den.modInverse(p))
                            .mod(p);
                }
                // System.out.printf(
                // " term i=%d: aᵢ=%s λᵢ=%s aᵢ·λᵢ=%s%n",
                // i,
                // ai.toString(16),
                // lambda.toString(16),
                // ai.multiply(lambda).mod(p).toString(16));

                sRec = sRec.add(ai.multiply(lambda)).mod(p);
            }
            // System.out.println("⇒ sRec = " + sRec.toString(16));

            return sRec;
        }

        /**
         * Reconstructs the dealer’s public share S = s·G via Lagrange interpolation
         * at α₀, from t+1 Shamir shares A_i = m(α_i)·G.
         *
         * @param ctx     the NAP-DKG context holding (G, p, alphas[], …)
         * @param shares  an array of Share objects A_i = m(α_i)·G for i∈I
         * @param indices the matching 1-based indices i ∈ I (|I| = t+1)
         * @return the reconstructed ECPoint S = s·G
         */
        public static ECPoint reconstructSecretEC(DkgContext ctx,
                Share[] shares,
                int[] indices) {
            if (shares.length != indices.length) {
                throw new IllegalArgumentException("share count ≠ indices count");
            }

            BigInteger p = ctx.getOrder();
            BigInteger[] alphas = ctx.getAlphas(); // [α₀, α₁, …, αₙ]
            BigInteger x0 = alphas[0]; // interpolate at α₀
            ECPoint Srec = ctx.getGenerator()
                    .getCurve()
                    .getInfinity();

            for (int k = 0; k < shares.length; k++) {
                int i = indices[k];
                ECPoint Ai = shares[k].getAiPoint();
                BigInteger lambda = BigInteger.ONE;

                // ℓᵢ = ∏_{j≠i}(α₀−αⱼ)/(αᵢ−αⱼ) mod p
                for (int m = 0; m < shares.length; m++) {
                    if (m == k)
                        continue;
                    int j = indices[m];
                    BigInteger num = x0.subtract(alphas[j]).mod(p);
                    BigInteger den = alphas[i].subtract(alphas[j]).mod(p);
                    lambda = lambda
                            .multiply(num)
                            .multiply(den.modInverse(p))
                            .mod(p);
                }
                log.info(String.format(
                        "   • Dealer idx=%d  α_i=%s  → λ_i = %s",
                        i, // zero‐based dealer index
                        alphas[i].toString(16), // α_i in hex
                        lambda.toString(16) // λ_i in hex
                ));
                ECPoint termPoint = Ai.multiply(lambda).normalize();
                log.info(String.format(
                        "     → A_{%d} = %s\n       so A_{%d}·λ_%d = %s",
                        i,
                        Hex.toHexString(Ai.getEncoded(true)),
                        i, i,
                        Hex.toHexString(termPoint.getEncoded(true))));

                Srec = Srec.add(Ai.multiply(lambda));
                log.info(" ⇒ In reconstructSecretEC: final Srec = {}", Hex.toHexString(Srec.getEncoded(true)));

            }
            // System.out.println("⇒ sRec = " + Srec);

            return Srec.normalize();
        }
    }
}
