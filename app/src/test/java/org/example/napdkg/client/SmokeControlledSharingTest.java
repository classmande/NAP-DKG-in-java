package org.example.napdkg.client;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.core.DHPVSS_Setup;
import org.example.napdkg.core.DhKeyPair;
import org.example.napdkg.core.PartyContext;
import org.example.napdkg.core.PublicKeysWithProofs;
import org.example.napdkg.core.Share;
import org.example.napdkg.core.SharingPhase;
import org.example.napdkg.dto.EphemeralKeyDTO;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.DkgUtils;

import org.example.napdkg.util.GroupGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A “controlled” smoke‐test for SharingPhase.
 * 
 * Now updated so that the ephemeral keys for each party are truly random
 * instead of G^1, G^2, ... .
 */
public class SmokeControlledSharingTest {
    private static final Logger log = LoggerFactory.getLogger(SmokeControlledSharingTest.class);

    public static void main(String[] args) throws Exception {
        // ----------------------------------------------------------------
        int n = 6;
        int t = 3;
        int fa = 1;

        // (exactly your lines)
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DkgContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        // Instead of HttpPbbClient, use a dummy that never blocks,
        // returning truly random ephemeral public keys for each party:
        PbbClient dummyPbb = new DummyPbbClient(ctx);

        // Build PartyContext list with our dummyPbb:
        List<PartyContext> parties = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            parties.add(new PartyContext(i, ctx, dummyPbb, n, t, fa));
        }

        // ----------------------------------------------------------------
        // 2) Pick Party 0’s "dealer" and overwrite its ephemeral key:
        // ----------------------------------------------------------------
        PartyContext dealerCtx = parties.get(0);
        // Overwrite ephemeral‐key pair so getSecretKey() and getPublic() are valid:
        dealerCtx.ephKey = DhKeyPair.generate(ctx);

        // ----------------------------------------------------------------
        // 3) Instantiate our TestSharingPhase subclass for party 0:
        // ----------------------------------------------------------------
        TestSharingPhase testDealer = new TestSharingPhase(dealerCtx, t);

        // 4) Build a random polynomial c0=s, c1, c2 < p:
        BigInteger p = ctx.getOrder();
        // c0 = s is fixed, for demonstration
        BigInteger s = new BigInteger("65abe13aef2ec15f25ff33327b6cdf7e8be046efebb9380f48943aabcdfb1aaf", 16);

        SecureRandom rnd = new SecureRandom();
        BigInteger c1 = new BigInteger(p.bitLength(), rnd).mod(p);
        BigInteger c2 = new BigInteger(p.bitLength(), rnd).mod(p);

        BigInteger[] fixedCoeffs = new BigInteger[] { s, c1, c2 };

        // 5) Call runSharingAsDealerWithFixedPoly (bypasses deriveFirstRoundPoly)
        testDealer.runSharingAsDealerWithFixedPoly(s, fixedCoeffs);

        System.out.println("\n==== SMOKE TEST COMPLETE ====");
    }

    /**
     * A small fake PbbClient that, whenever fetch("ephemeralKeys", ...) is called,
     * returns ephemeral public keys that are truly random, instead of G^1, G^2,...
     *
     * We store them in ephemeralPubs so that each fetch returns the same set.
     */
    private static class DummyPbbClient implements PbbClient {
        private final DkgContext ctx;
        private final List<BigInteger> ephemeralSecrets = new ArrayList<>();
        private final List<ECPoint> ephemeralPubs = new ArrayList<>();
        private boolean alreadyGenerated = false;

        DummyPbbClient(DkgContext ctx) {
            this.ctx = ctx;
        }

        @SuppressWarnings("unchecked")
        @Override
        public <T> List<T> fetch(String topic, Class<T> clazz) {
            if (!topic.equals("ephemeralKeys")) {
                throw new IllegalArgumentException("DummyPbbClient only knows ephemeralKeys");
            }
            // If we haven't generated ephemeral keys yet, do so now.
            if (!alreadyGenerated) {
                generateRandomEphemeralKeys(ctx.getNumParticipants());
                alreadyGenerated = true;
            }
            // Convert ephemeralPubs to EphemeralKeyDTO
            List<EphemeralKeyDTO> dtos = new ArrayList<>();
            for (int i = 0; i < ephemeralPubs.size(); i++) {
                ECPoint pubPt = ephemeralPubs.get(i);
                String hexPub = Hex.toHexString(pubPt.getEncoded(true));
                String id = "RandomParty " + i;
                // We won't bother with a real proof -> "0|0"
                EphemeralKeyDTO dto = new EphemeralKeyDTO(id, i, hexPub, "0|0");
                dtos.add(dto);
            }
            return (List<T>) (List<?>) dtos;
        }

        private void generateRandomEphemeralKeys(int n) {
            ECPoint G = ctx.getGenerator();
            BigInteger order = ctx.getOrder();
            SecureRandom rnd = new SecureRandom();

            for (int i = 0; i < n; i++) {
                BigInteger sk = new BigInteger(order.bitLength(), rnd).mod(order);
                ECPoint pubPt = G.multiply(sk).normalize();
                ephemeralSecrets.add(sk);
                ephemeralPubs.add(pubPt);
                System.out.println("DummyPbbClient created ephemeral SK[" + i + "]=" + sk.toString(16)
                        + " => pub E[" + i + "]=" + pubPt);
            }
        }

        @Override
        public void publish(String topic, Object dto) {
            // no‐op
        }

        @Override
        public void delete(String topic, String id) throws Exception {
            // no‐op
        }
    }

    /**
     * Our “test” subclass of SharingPhase.
     * Overridden so it fetches random ephemeral pubkeys from DummyPbbClient
     * and uses them to build aggregator sums.
     */
    public static class TestSharingPhase extends SharingPhase {
        public TestSharingPhase(PartyContext P, int t) {
            super(P, t);
            // Overwrite the (protected) myEphKey so it is never null:
            this.myEphKey = DhKeyPair.generate(ctx);
        }

        @Override
        public List<PublicKeysWithProofs> fetchEph() throws Exception {
            // Use the PBB client to fetch ephemeral keys (which are random in this version)
            List<EphemeralKeyDTO> dtos = (List<EphemeralKeyDTO>) pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class);

            List<PublicKeysWithProofs> pubs = new ArrayList<>();
            for (EphemeralKeyDTO dto : dtos) {
                byte[] pubBytes = Hex.decode(dto.publicKey);
                ECPoint pubPt = ctx.getCurve().decodePoint(pubBytes).normalize();
                // We do not really need a valid proof, so pass "null":
                pubs.add(new PublicKeysWithProofs(dto.partyIndex, pubPt, /* dummyProof= */null));
            }
            return pubs;
        }

        /**
         * Exactly like SharingPhase.runSharingAsDealer(), except:
         * • We do NOT call HashingTools.deriveFirstRoundPoly().
         * • We assume the “fixedCoeffs” array is the polynomial [c0,c1,c2].
         * • We skip publishing; we only build U,V and check U^s == V.
         */
        public void runSharingAsDealerWithFixedPoly(BigInteger s, BigInteger[] fixedCoeffs) throws Exception {
            BigInteger p = ctx.getOrder();
            ECPoint G = ctx.getGenerator();

            System.out.println("\n==== Smoke-Controlled SharingPhase Test Begin ====\n");
            System.out.println("Dealer (id=" + me + ") picked s = " + s.toString(16));

            // 1) Shamir shares a_{i,j} = poly(alpha[j])
            BigInteger[] alpha = ctx.getAlphas();
            Share[] sh = new Share[n];
            for (int j = 1; j <= n; j++) {
                BigInteger aij = DkgUtils.evaluatePolynomial(fixedCoeffs, alpha[j], p);
                ECPoint Aij = G.multiply(aij).normalize();
                sh[j - 1] = new Share(aij, Aij);
                System.out.printf("Shamir share for alpha[%d] = %s%n", j, aij.toString(16));
            }

            // 2) Fetch ephemeral pubkeys E[0..n-1]
            List<PublicKeysWithProofs> eph = fetchEph();
            ECPoint[] E = new ECPoint[n];
            for (int j = 0; j < n; j++) {
                E[j] = eph.get(j).getPublicKey();
            }

            // 3) C_{i,j} = E[j]^{sk_i} + A_{i,j}
            BigInteger sk_i = myEphKey.getSecretKey();
            System.out.println("myEphKey.getSecretKey() = " + sk_i.toString(16));
            ECPoint pk_i = myEphKey.getPublic();

            ECPoint[] Cij = new ECPoint[n];
            for (int j = 0; j < n; j++) {
                BigInteger aij = sh[j].getai();
                ECPoint Aij = sh[j].getAiPoint();
                Cij[j] = E[j].multiply(sk_i).add(Aij).normalize();
                System.out.println("We used C_{i," + (j + 1) + "} = E[" + (j + 1) +
                        "]^sk_i + A_{i," + (j + 1) + "}");
            }

            // 4) aggregator sums
            BigInteger[] v = ctx.getVs(); // Lagrange-like coefficients
            ECPoint U = G.getCurve().getInfinity();
            ECPoint V = U;

            System.out.println("\n==== TINY SCRAPE DEBUG BEGIN ====");
            System.out.println("  ➜ SCRAPE weights v[] = " + java.util.Arrays.toString(v));

            System.out.print("  ➜ Polynomial m*(x) coeffs = [");
            for (int i = 0; i < fixedCoeffs.length; i++) {
                System.out.print(fixedCoeffs[i].toString(16));
                if (i + 1 < fixedCoeffs.length)
                    System.out.print(", ");
            }
            System.out.println("]");

            for (int j = 1; j <= n; j++) {
                BigInteger eval = DkgUtils.evaluatePolynomial(fixedCoeffs, alpha[j], p);
                BigInteger w = v[j - 1].multiply(eval).mod(p);

                System.out.printf(
                        "    j=%d: α[%d]=%s,  m*(α)=%s,  v[%d]=%s,  r[%d]=%s%n",
                        j, j,
                        alpha[j].toString(16),
                        eval.toString(16),
                        j, v[j - 1].toString(16),
                        j, w.toString(16));

                ECPoint addU = E[j - 1].multiply(w).normalize();
                ECPoint addV = Cij[j - 1].multiply(w).normalize();
                U = U.add(addU).normalize();
                V = V.add(addV).normalize();

                System.out.println("      → partial U = " + U);
                System.out.println("      → partial V = " + V);
            }

            // 5) optional check: sum(r[j]) mod p => ?
            BigInteger sumR = BigInteger.ZERO;
            for (int j = 1; j <= n; j++) {
                BigInteger eval = DkgUtils.evaluatePolynomial(fixedCoeffs, alpha[j], p);
                BigInteger rj = v[j - 1].multiply(eval).mod(p);
                sumR = sumR.add(rj).mod(p);
            }
            System.out.println("  ➜ ∑_{j=1..n} r[j] mod p = " + sumR.toString(16) + "  (should be 0 or random)");

            System.out.println("\n  ➜ Final aggregator U = " + U);
            System.out.println("  ➜ Final aggregator V = " + V);

            ECPoint check = U.multiply(sk_i).normalize();
            System.out.println("  ➜ Check U^sk_i = " + check);
            if (check.equals(V)) {
                System.out.println("  ✔ SCRAPE passed");
            } else {
                System.out.println("  ⛔ SCRAPE failed (U^ski != V)!");
                throw new IllegalStateException("😞  SCRAPE aggregator test failed: U^ski != V");
            }
            System.out.println("==== TINY SCRAPE DEBUG END ====");
        }
    }
}
