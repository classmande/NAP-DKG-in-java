package org.example.napdkg.core;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.dto.EphemeralKeyDTO;
import org.example.napdkg.dto.SharingOutputDTO;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.HashingTools;
import org.example.napdkg.util.MaskedShareCHat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class for the Sharing (1st round.) in the protocol:
 * Follows 7 steps.
 */

public class SharingPhase {
  private static final Logger log = LoggerFactory.getLogger(SharingPhase.class);
  protected final DkgContext ctx;
  protected final PbbClient pbb;
  protected final int me;

  protected final int n;

  protected final int t;
  private final SecureRandom rnd = new SecureRandom();
  protected BigInteger secretShare;
  protected DhKeyPair myEphKey;

  public SharingPhase(PartyContext P, int t) {
    this.ctx = P.ctx;
    this.pbb = P.pbb;
    this.me = P.id;
    this.n = P.allEphPubs.length;
    this.t = t;
    this.myEphKey = P.ephKey;
  }

  public BigInteger getSecretShare() {
    return secretShare;
  }

  /** Fetch all public keys with proof and decode them from the DTO. */
  public List<PublicKeysWithProofs> fetchEph() throws Exception {
    List<EphemeralKeyDTO> dtos = pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class);
    List<PublicKeysWithProofs> pubs = new ArrayList<>();
    for (EphemeralKeyDTO dto : dtos) {
      byte[] raw = Hex.decode(dto.publicKey);
      ECPoint P = ctx.getGenerator().getCurve().decodePoint(raw).normalize();
      String[] parts = dto.schnorrProof.split("\\|");
      BigInteger challenge = new BigInteger(parts[0], 16);
      BigInteger response = new BigInteger(parts[1], 16);
      NizkDlProof proof = new NizkDlProof(challenge, response);
      pubs.add(new PublicKeysWithProofs(dto.partyIndex, P, proof));
    }
    return pubs;
  }

  public void runSharingAsDealer() throws Exception {
    BigInteger p = ctx.getOrder();
    ECPoint G = ctx.getGenerator();

    // --------------------------------------------
    // 1) Dealer picks random secret s ∈ Z_p Using SecureRandom: cryptographically
    // strong random number generator (RNG).
    // --------------------------------------------

    BigInteger s = new BigInteger(p.bitLength(), rnd).mod(p);
    this.secretShare = s; // store your "dealer" secret if needed

    // --------------------------------------------
    // 2) Shamir-share “s” among n parties
    // --------------------------------------------

    GShamirShareDKG.ShamirSharingResult res = GShamirShareDKG.ShamirSharingResult.generateShares(ctx, s);

    // Each 'Share' has getai() = scalar share, getAiPoint() = G^(ai).
    Share[] shares = res.shares; // length n
    BigInteger[] coeffs = res.coeffs; // the polynomial coefficients behind the scenes

    BigInteger[] alpha = ctx.getAlphas(); // alpha[i] = distinct x-coords for the shares
    BigInteger[] v = ctx.getVs(); // v[i] = Lagrange-like coefficient for i-th point

    // --------------------------------------------
    // 3) For all i →[n] compute Ci,j = ski·Ej + Ai,j and Ci,j = H→(Ai,j ) ⇒ai,j.
    // --------------------------------------------

    // --------------------------------------------
    // 3.1) Gather Aij = G^{aij} and scalars aij
    // --------------------------------------------

    ECPoint[] Aij = new ECPoint[n];
    BigInteger[] aijScalars = new BigInteger[n];
    for (int j = 0; j < n; j++) {
      aijScalars[j] = shares[j].getai().mod(p);
      Aij[j] = shares[j].getAiPoint(); // G^(aij)
    }

    // --------------------------------------------
    // 3.2) Fetch ephemeral keys E[1..n], own ephemeral secret key
    // --------------------------------------------
    List<PublicKeysWithProofs> eph = fetchEph(); // e.g. from PBB
    ECPoint[] E = new ECPoint[n];
    for (int j = 0; j < n; j++) {
      // ephemeral public keys from others
      E[j] = eph.get(j).getPublicKey().normalize();
    }

    // ephemeral secret key for "this" dealer
    BigInteger ski = myEphKey.getSecretKey();
    ECPoint pk_i = myEphKey.getPublic(); // G^(ski)

    // --------------------------------------------
    // 3.3 Compute masked shares: C[j] = E[j]^ski + Aij[j]
    // and the "CHat" = masked scalar
    // --------------------------------------------

    ECPoint[] Cij = new ECPoint[n];
    BigInteger[] CHat = new BigInteger[n];

    for (int j = 0; j < n; j++) {
      // C_ij = E[j]*ski + Aij
      Cij[j] = E[j].multiply(ski).add(Aij[j]).normalize();

      // CHat might be something
      CHat[j] = MaskedShareCHat.maskShare(Aij[j], aijScalars[j], p);

    }
    // ------------------------------------------
    // 4) Derive aggregator polynomial m*(X)
    // For NAP-DKG, hashed from all pk_i, Cij, CHat, e
    // --------------------------------------------

    BigInteger[] mStar = HashingTools.deriveMStar(
        ctx, pk_i, E, Cij, CHat, n, t);

    // =========================================================================
    // 5. Set V and U
    // U = ∑ v_j * m*(α_j) * E[j]
    // V = ∑ v_j * m*(α_j) * Cij[j]
    // Then check if V == U^ski (or do a DLEQ proof).
    // =========================================================================

    ECPoint U = G.getCurve().getInfinity();
    ECPoint V = G.getCurve().getInfinity();
    for (int j = 1; j <= n; j++) {
      BigInteger evalMj = evaluatePolynomial(mStar, alpha[j], p);
      BigInteger factor = v[j - 1].multiply(evalMj).mod(p);

      // Debug prints:

      U = U.add(E[j - 1].multiply(factor)).normalize();
      V = V.add(Cij[j - 1].multiply(factor)).normalize();
    }

    System.out.println("Final aggregator U=" + U + "\nFinal aggregator V=" + V);

    ECPoint UtoSki = U.multiply(ski).normalize();
    System.out.println("U^ski=" + UtoSki);

    // Compare with V
    if (!UtoSki.equals(V)) {
      System.out.println("Aggregator check FAIL");
    } else {
      System.out.println("Aggregator check PASS");
    }

    // Then check U^ski vs. V
    UtoSki = U.multiply(ski).normalize();
    boolean match = UtoSki.equals(V);
    System.out.println("Aggregator check match? => " + match);

    // Check aggregator condition: does U^ski == V ?

    boolean aggregatorScrapeOK = UtoSki.equals(V);
    if (aggregatorScrapeOK) {
      System.out.println("✔ Aggregator-based SCRAPE verification PASSED");
    } else {
      System.out.println("⛔ Aggregator-based SCRAPE verification FAILED");
    }

    // --------------------------------------------
    // 6) Generate DLEQ proof that ski is consistent
    // with pk_i = G^ski and V = U^ski
    // --------------------------------------------

    NizkDlEqProof proof = NizkDlEqProof.generateProof(ctx, pk_i, U, V, ski);
    boolean verify = NizkDlEqProof.verifyProof(ctx, pk_i, U, V, proof);
    System.out.println("DLEQ verify = " + verify);

    // --------------------------------------------
    // 6.1) (Optional) Quick share correctness check
    // Evaluate polynomial at alpha[i] and compare.
    // --------------------------------------------

    for (int i = 1; i <= n; i++) {
      BigInteger expected = evaluatePolynomial(coeffs, alpha[i], p);
      BigInteger actual = shares[i - 1].getai();
      if (!expected.equals(actual)) {
        System.err.printf("Share mismatch at i=%d: expected=%s actual=%s\n",
            i, expected, actual);
      }
    }

    // --------------------------------------------
    // 7) Publish the masked shares + proof
    // --------------------------------------------

    SharingOutput out = new SharingOutput(
        me, // or "dealer ID"
        me,
        pk_i, // ephemeral public key
        Cij,
        CHat,
        proof);
    SharingOutputDTO dto = SharingOutputDTO.from(out);
    // if (dto.id == null || dto.id.isEmpty()) {
    // dto.id = java.util.UUID.randomUUID().toString();
    // }

    log.info("pk_i for PBB dealer {} = (dto){}", me, dto.dealerPub);
    pbb.publish("DealerPublish", dto);
  }

  // Correct polynomial evaluation method
  public static BigInteger evaluatePolynomial(BigInteger[] coeffs, BigInteger x, BigInteger p) {
    BigInteger result = coeffs[coeffs.length - 1];
    for (int i = coeffs.length - 2; i >= 0; i--) {
      result = result.multiply(x).add(coeffs[i]).mod(p);
    }
    return result;
  }

}
