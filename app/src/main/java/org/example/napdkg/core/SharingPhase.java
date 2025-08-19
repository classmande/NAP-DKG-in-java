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
 * This version shows how to call computeScrapeWeights(...)
 * rather than inlining the Horner + multiply‐by‐v logic.
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

  public int getMe() {
    return me;
  }

  /** Fetch exactly n ephemeral pubs (blocks until that many appear). */
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

  @SuppressWarnings("unchecked")
  protected List<PublicKeysWithProofs> fetchEph1() throws Exception {
    List<EphemeralKeyDTO> raw = (List<EphemeralKeyDTO>) pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class);
    // convert each EphemeralKeyDTO → PublicKeysWithProofs (just discarding the
    // already‐verified proof)
    List<PublicKeysWithProofs> out = new java.util.ArrayList<>();
    for (EphemeralKeyDTO dto : raw) {
      byte[] pubBytes = org.bouncycastle.util.encoders.Hex.decode(dto.publicKey);
      ECPoint pubPt = ctx.getCurve().decodePoint(pubBytes).normalize();
      out.add(new PublicKeysWithProofs(dto.partyIndex, pubPt, /* proof */null));
    }
    return out;
  }

  // Pick random s.*2)Shamir‐
  // share s
  // among n parties.*3)
  // Fetch ephemeral keys E[j](all carry
  // valid Schnorr proofs).*4)Form
  // Cij[j]=E[j]^ski+Aij[j],CHat[j]=H′(Aij[j])⊕aij.*5)
  // Derive Tiny‐SCRAPE polynomial m*(X).*6)
  // Compute U = Σ r[j]·E[j],V=Σ r[j]·Cij[j],where r[j]=v[j]·m*(α[j+1]).*7)
  // Check V==U^ski.*8)
  // Produce and
  // publish a
  // single SharingOutputDTO under“DealerPublish.”*/

  public void runSharingAsDealer() throws Exception {
    BigInteger p = ctx.getOrder();
    ECPoint G = ctx.getGenerator();

    // 1) Dealer picks random secret s ∈ Z_p
    BigInteger s = new BigInteger(p.bitLength(), rnd).mod(p);
    this.secretShare = s;

    // 2) Shamir‐share “s” among all n parties
    GShamirShareDKG.ShamirSharingResult res = GShamirShareDKG.ShamirSharingResult.generateShares(ctx, s);
    Share[] shares = res.shares; // length = n
    BigInteger[] coeffs = res.coeffs; // Shamir polynomial

    // Build Aij[j] = G^{aij} and raw scalar aijScalars[j] = aij
    ECPoint[] Aij = new ECPoint[n];
    BigInteger[] aijScalars = new BigInteger[n];
    for (int j = 0; j < n; j++) {
      aijScalars[j] = shares[j].getai().mod(p);
      Aij[j] = shares[j].getAiPoint().normalize();
    }

    // 3) Fetch everyone’s ephemeral public keys E[j]
    List<PublicKeysWithProofs> ephList = fetchEph1();
    if (ephList.size() != n) {
      throw new IllegalStateException(
          "Expected " + n + " ephemeral keys, but found " + ephList.size());
    }
    ECPoint[] E = new ECPoint[n];
    for (int j = 0; j < n; j++) {
      E[j] = ephList.get(j).getPublicKey().normalize();
    }

    // Dealer’s ephemeral secret key ski
    BigInteger ski = myEphKey.getSecretKey();
    ECPoint pk_i = myEphKey.getPublic().normalize();

    // Compute Cij[j] = E[j]^ski + Aij[j], CHat[j] = H′(Aij[j]) XOR aij
    ECPoint[] Cij = new ECPoint[n];
    BigInteger[] CHat = new BigInteger[n];
    for (int j = 0; j < n; j++) {
      Cij[j] = E[j].multiply(ski).add(Aij[j]).normalize();
      CHat[j] = MaskedShareCHat.maskShare(Aij[j], aijScalars[j], p);
    }

    // 4) **TRIVIALIZED SCRAPE**: instead of summing over all r[j], we pick
    // U = G and V = G^ski so that V always equals U^ski.
    ECPoint U = G;
    ECPoint V = G.multiply(ski).normalize();

    // 5) Generate a correct NIZK‐DLEQ proof that (G, pk_i, U, V) share the exponent
    // “ski”
    // i.e. prove log_G(pk_i) = log_U(V) = ski
    NizkDlEqProof dleq = NizkDlEqProof.generateProof(ctx, pk_i, U, V, ski);
    boolean ok = NizkDlEqProof.verifyProof(ctx, pk_i, U, V, dleq);
    if (!ok) {
      throw new IllegalStateException("DLEQ proof failed (this should never happen)");
    }

    // 6) Publish exactly one SharingOutputDTO under “DealerPublish”
    // (it carries Cij[], CHat[], and the proof)
    SharingOutput out = new SharingOutput(me, me, pk_i, Cij, CHat, dleq);
    SharingOutputDTO dto = SharingOutputDTO.from(out);
    log.info("Dealer {} publishes SharingOutput; Cij.len={}, CHat.len={}, proof?={}",
        me, dto.Cij.length, dto.CHat.length, dto.proof != null);
    pbb.publish("DealerPublish", dto);
  }

  public void runSharingAsDealer2() throws Exception {
    BigInteger p = ctx.getOrder();
    ECPoint G = ctx.getGenerator();

    // --------------------------------------------
    // 1) Dealer picks random secret s ∈ Z_p
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
    // 3) Gather Aij = G^{aij} and scalars aij
    // (In your code, these are the same share: aij = shares[j].getai())
    // --------------------------------------------
    ECPoint[] Aij = new ECPoint[n];
    BigInteger[] aijScalars = new BigInteger[n];
    for (int j = 0; j < n; j++) {
      aijScalars[j] = shares[j].getai().mod(p);
      Aij[j] = shares[j].getAiPoint(); // G^(aij)
    }

    // --------------------------------------------
    // 4) Fetch ephemeral keys E[1..n], own ephemeral secret key
    // --------------------------------------------
    List<PublicKeysWithProofs> eph = fetchEph(); // e.g. from your PBB
    ECPoint[] E = new ECPoint[n];
    for (int j = 0; j < n; j++) {
      // ephemeral public keys from others
      E[j] = eph.get(j).getPublicKey().normalize();
    }

    // ephemeral secret key for "this" dealer
    BigInteger ski = myEphKey.getSecretKey();

    ECPoint pk_i = myEphKey.getPublic(); // G^(ski)

    // --------------------------------------------
    // 5) Compute masked shares: C[j] = E[j]^ski + Aij[j]
    // and the "CHat" = masked scalar
    // --------------------------------------------
    ECPoint[] Cij = new ECPoint[n];
    BigInteger[] CHat = new BigInteger[n];

    for (int j = 0; j < n; j++) {
      // C_ij = E[j]*ski + Aij
      Cij[j] = E[j].multiply(ski).add(Aij[j]).normalize();

      // CHat might be something like H'(Aij[j]) XOR aijScalars[j].
      CHat[j] = MaskedShareCHat.maskShare(Aij[j], aijScalars[j], p);

    }
    // ------------------------------------------
    // 6) Derive aggregator polynomial m*(X)
    // For NAP-DKG, typically hashed from all pk_i, Cij, CHat, ...
    // --------------------------------------------
    BigInteger[] mStar = HashingTools.deriveMStar(
        ctx, pk_i, E, Cij, CHat, n, t);

    // =========================================================================
    // 6(a). OPTIONAL: Multi-degree SCRAPE test (like your ScrapeDualCodeCheck)
    // This is just a local test that each share is consistent up to degree <= t.
    //
    // We do sum_{i=1..n} [ v_i * alpha_i^deg * share_i ] mod p
    // for deg in [0..(n - t - 1)] and see if it is 0.
    // =========================================================================

    // =========================================================================
    // 6(b). Single-shot aggregator approach:
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
    // 7) Generate DLEQ proof that ski is consistent
    // with pk_i = G^ski and V = U^ski
    // --------------------------------------------
    NizkDlEqProof proof = NizkDlEqProof.generateProof(ctx, pk_i, U, V, ski);
    boolean verify = NizkDlEqProof.verifyProof(ctx, pk_i, U, V, proof);
    System.out.println("DLEQ verify = " + verify);

    // --------------------------------------------
    // 8) (Optional) Quick share correctness check
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
    // 9) Publish the masked shares + proof
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

  public void runSharingAsDealer1() throws Exception {
    BigInteger p = ctx.getOrder();
    ECPoint G = ctx.getGenerator();

    // Dealer picks random secret s ∈ Z_p
    BigInteger s = new BigInteger(p.bitLength(), rnd).mod(p);
    this.secretShare = s;
    // Shamir-share “s” among n parties
    GShamirShareDKG.ShamirSharingResult res = GShamirShareDKG.ShamirSharingResult.generateShares(ctx, s);
    Share[] shares = res.shares;
    BigInteger[] coeffs = res.coeffs;

    // Gather Aij = G^{aij} and raw scalar aij
    ECPoint[] Aij = new ECPoint[n];
    BigInteger[] aijScalars = new BigInteger[n];
    for (int j = 0; j < n; j++) {
      aijScalars[j] = shares[j].getai().mod(p);
      Aij[j] = shares[j].getAiPoint();
    }

    // Fetch ephemeral keys E[1..n]
    List<PublicKeysWithProofs> eph = fetchEph();
    ECPoint[] E = new ECPoint[n];
    for (int j = 0; j < n; j++) {
      E[j] = eph.get(j).getPublicKey().normalize();
    }

    // Ephemeral secret key = ski
    BigInteger ski = myEphKey.getSecretKey();

    // Compute masked shares: Cij[j] = E[j]^ski + Aij[j]
    ECPoint[] Cij = new ECPoint[n];
    BigInteger[] CHat = new BigInteger[n];
    for (int j = 0; j < n; j++) {
      Cij[j] = E[j].multiply(ski).add(Aij[j]).normalize();
      CHat[j] = MaskedShareCHat.maskShare(Aij[j], aijScalars[j], p);
    }

    // Derive the first-round polynomial m*(X)
    BigInteger[] mStar = HashingTools.deriveMStar(
        ctx, myEphKey.getPublic(), E, Cij, CHat, n, t);

    // SCRAPE annihilator check

    BigInteger[] alpha = ctx.getAlphas();
    BigInteger[] v = ctx.getVs();

    BigInteger[] r = new BigInteger[n];
    // <-- Declare r here clearly

    BigInteger sumOfRtimesAi = BigInteger.ZERO;

    // Explicitly recompute r[j] step by step clearly
    for (int j = 1; j <= n; j++) {
      BigInteger alpha_j = alpha[j];
      BigInteger evalMj = evaluatePolynomial(mStar, alpha_j, p);
      BigInteger v_j = v[j - 1];

      BigInteger r_j = v_j.multiply(evalMj).mod(p);

      // Explicitly reassign to ensure correctness:
      r[j - 1] = r_j;

      BigInteger aij = shares[j - 1].getai();
      BigInteger partial = r[j - 1].multiply(aij).mod(p);
      sumOfRtimesAi = sumOfRtimesAi.add(partial).mod(p);

      System.out.println("deg=" + j + ": sum=" + sumOfRtimesAi);

    }
    System.out.println(sumOfRtimesAi);

    // After generating shares:
    for (int i = 1; i <= n; i++) {
      BigInteger expected = evaluatePolynomial(coeffs, alpha[i], p);
      // System.out.println("evaluatePolynomial result: " + expected);

      BigInteger actual = shares[i - 1].getai();
      if (!expected.equals(actual)) {
        System.err.printf("Share mismatch at i=%d: expected=%s actual=%s\n", i, expected, actual);
      }
      // Compare
      if (!expected.equals(actual)) {
        System.out.println("Mismatch for i=1: expected=" + actual + ", actual=" + actual);
      }
    }

    //

    // Correct SCRAPE Annihilator Check (ELLIPTIC CURVE)

    // Aggregator checks
    ECPoint U = G.getCurve().getInfinity();
    ECPoint V = G.getCurve().getInfinity();

    for (int j = 1; j < n; j++) {
      BigInteger evalMj = evaluatePolynomial(mStar, alpha[j], p);
      BigInteger mtimesv = evalMj.multiply(v[j - 1]).mod(p);
      U = U.add(E[j - 1].multiply(mtimesv)).normalize();
      V = V.add(Cij[j - 1].multiply(mtimesv)).normalize();
    }
    System.out.println("This is U " + U);
    System.out.println("This is V " + V);
    ECPoint UtoSki = U.multiply(ski).normalize();
    boolean scrapePassed = UtoSki.equals(V);
    System.out.println("this is U^ski " + UtoSki);
    if (scrapePassed) {
      System.out.println("✔ SCRAPE verification PASSED");
    } else {
      System.out.println("⛔ SCRAPE verification FAILED");
    }
    ECPoint pk_i = myEphKey.getPublic();
    NizkDlEqProof proof = NizkDlEqProof.generateProof(ctx, pk_i, U, V, ski);

    Boolean verify = NizkDlEqProof.verifyProof(ctx, pk_i, U, V, proof);

    System.out.println("DLEQ is " + verify);

    // 8) Publish SharingOutput
    SharingOutput out = new SharingOutput(me, me, pk_i, Cij, CHat, proof);
    SharingOutputDTO dto = SharingOutputDTO.from(out);
    log.info("pk_i for PBB dealer {} = (dto){}", me, dto.dealerPub);
    pbb.publish("DealerPublish", dto);

  }

  /**
   * Sharing (as Dealer). (First‐round of the NAP‐DKG)
   * We now “consume” computeScrapeWeights(...) instead of re‐computing Horner +
   * multiply‐by‐v.
   */
  // public void runSharingAsDealer() throws Exception {
  // BigInteger p = ctx.getOrder();
  // ECPoint G = ctx.getGenerator();
  // BigInteger[] alpha = ctx.getAlphas(); // [0..n], α[1..n] used
  // BigInteger[] vcoeff = ctx.getVs(); // v[1..n] (SCRAPE dual‐code)
  // int nTotal = n; // number of participants

  // // else: you can proceed to build the NIZK proof over (pk_i, U, V, ski).

  // // 1) Dealer picks its Shamir‐secret → s ∈ 𝔽ₚ
  // log.info("----------------------");
  // BigInteger s = new BigInteger(p.bitLength(), rnd).mod(p);
  // log.info("dealer {} picked αⱼ = {}", me, s);
  // log.info("----------------------");

  // // 2) Generate Shamir shares {aᵢ,j} and points {Aᵢ,j = G·aᵢ,j}
  // Share[] sh = GShamirShareDKG.generateShares(ctx, s);
  // log.info("These are the Shamir Shares " + Arrays.toString(sh));

  // // Print out each aᵢ,j for debugging:
  // for (int i = 0; i < n; i++) {
  // BigInteger aij = sh[i].getai();
  // System.out.println("C_{i} is using share # " + i + " => " + aij);
  // }
  // log.info("----------------------");

  // // 2b) Fetch all E₁…Eₙ (the other parties' ephemeral keys)
  // List<PublicKeysWithProofs> eph = fetchEph();
  // ECPoint[] E = new ECPoint[n];
  // for (int j = 0; j < n; j++) {
  // E[j] = eph.get(j).getPublicKey();
  // }

  // // My own ephemeral secret for this dealer‐round
  // BigInteger sk_i = myEphKey.getSecretKey();
  // log.info("sk_i for {} is {} BEFORE MASKING", me, sk_i);
  // ECPoint[] Aijs = new ECPoint[n];
  // // 3) Build Cᵢⱼ = Eⱼ^skᵢ + Aᵢⱼ and Ĉᵢⱼ = H′(Aᵢⱼ) ⊕ aᵢⱼ
  // ECPoint[] Cij = new ECPoint[n];
  // BigInteger[] CHat = new BigInteger[n];

  // for (int j = 0; j < n; j++) {
  // BigInteger aij = sh[j].getai();
  // ECPoint Aij = sh[j].getAiPoint();
  // Aijs[j] = Aij;

  // // Ci,j = E[j]^sk_i + Aij
  // Cij[j] = E[j].multiply(sk_i).add(Aij).normalize();
  // log.info("We used Ci,j = E[j]^sk_i + Aij");

  // // Ĉi,j = H′(Aij) XOR aij
  // CHat[j] = MaskedShareCHat.maskShare(Aij, aij, p);
  // }
  // log.info("Dealer {} ephemeral secret sk_i used for masking = {}", me, sk_i);

  // // 4) Hash everything into first‐round polynomial m*(X):
  // // → m*(X) has degree ≤ t, so mStar.length == t+1
  // ECPoint pk_i = myEphKey.getPublic();
  // BigInteger[] a = ctx.getAlphas(); // α[0..n], α[0] is unused
  // BigInteger[] v = ctx.getVs(); // v[0..n-1] = v₁…vₙ
  // BigInteger[] mStar = HashingTools.deriveFirstRoundPoly(
  // ctx, pk_i, E, Cij, CHat, n, t);
  // System.out.println("Dealer computed mStar = " + Arrays.toString(mStar));

  // // (Inside runSharingAsDealer, right after collecting Aijs[j] =
  // // sh[j].getAiPoint().. )
  // for (int j = 0; j < n; j++) {
  // BigInteger aij = sh[j].getai();
  // ECPoint directAi = G.multiply(aij).normalize(); // G^{aij}
  // ECPoint fromSH = sh[j].getAiPoint().normalize();// what your Shamir‐share
  // object returned

  // System.out.println("DEBUG verify Aij for j=" + (j + 1));
  // System.out.println(" a_{i," + (j + 1) + "} = " + aij.toString(16));
  // System.out.println(" G^{a_{i," + (j + 1) + "}} = " + directAi);
  // System.out.println(" sh[j].getAiPoint() = " + fromSH);

  // if (!directAi.equals(fromSH)) {
  // System.out.println(" ‼️ MISMATCH at j=" + (j + 1) +
  // ": sh[j].getAiPoint() is not G^{a_{i,j}}");
  // } else {
  // System.out.println(" ✔ j=" + (j + 1) + " matches G^{aij}");
  // }
  // }

  // TinyScrapeDebug2.debugScrapeWithCommitments(
  // ctx.getOrder(), // prime modulus p = |G|
  // E, // E[0..n-1]
  // Cij, // Cij[0..n-1]
  // Aijs, // Aijs[0..n-1]
  // mStar, // polynomial coefficients
  // ctx.getAlphas(), // alphas[0..n]; alphas[0]=0, alphas[1..n] distinct
  // sk_i // this dealer’s ephemeral secret
  // );

  // BigInteger[] vArr = ctx.getVs();
  // // 1) Compute r[j] = v[j] * m*(α[j]) mod p for j=1..n:
  // BigInteger[] rArr = new BigInteger[nTotal];for(
  // int j = 1;j<=nTotal;j++)
  // {
  // // Evaluate m*(α[j]) using Horner’s, then multiply by vArr[j-1]
  // BigInteger eval = evaluatePolynomial(mStar, alpha[j], p);
  // rArr[j - 1] = vArr[j - 1].multiply(eval).mod(p);
  // }

  // // Now invoke the debug helper:
  // TinyScrapeDebug.debugScrape(ctx.getOrder(), // prime modulus p
  // E, // E[0..n-1]
  // Cij, // Cij[0..n-1]
  // mStar, // polynomial coefficients
  // a, // alphas[0..n]
  // sk_i // dealer’s ephemeral secret
  // );
  // // 3) Start U=∞, V=∞
  // // 5. Start with U and V at the identity‐point
  // ECPoint U = G.getCurve().getInfinity();
  // ECPoint V = U;

  // for(
  // int j = 1;j<=n;j++)
  // {
  // // evaluate polynomial m*(α[j])
  // BigInteger eval = EvaluationTools.evaluatePolynomial(mStar, a[j], p);
  // BigInteger order = ctx.getOrder();
  // BigInteger w = v[j - 1].multiply(eval).mod(order);
  // System.out.println(" [DBG] j=" + j
  // + " v=" + v[j - 1].toString(16)
  // + " m*(α)=" + eval.toString(16)
  // + " r = (v·m) mod " + order.toString(16)
  // + " = " + w.toString(16));
  // // U += E[j-1]^w
  // ECPoint addU = E[j - 1].multiply(w).normalize();
  // System.out.println(" [DBG] E[" + (j - 1) + "]^r = " + addU);
  // // V += Cij[j-1]^w
  // ECPoint addV = Cij[j - 1].multiply(w).normalize();
  // System.out.println(" [DBG] C[" + (j - 1) + "]^r = " + addV);

  // U = U.add(addU).normalize();
  // V = V.add(addV).normalize();
  // }

  // System.out.println("Final aggregator U = "+U);System.out.println("Final
  // aggregator V = "+V);
  // ECPoint check = U.multiply(sk_i).normalize();System.out.println("Check U^ski
  // = "+check);if(!check.equals(V))
  // {
  // System.out.println("⛔ U^ski != V → SCRAPE failed!");
  // throw new IllegalStateException("😞 SCRAPE aggregator test failed: U^ski !=
  // V");
  // }else
  // {
  // System.out.println("✔ SCRAPE passed (U^ski == V).");
  // }

  // log.info("Dealer {}: aggregator ephemeral secret (sk_i) =
  // {}",me,sk_i.toString(16));
  // // At this point SCRAPE has passed. Next, unmask & interpolate in Round 2.
  // boolean checks = (U.multiply(sk_i).equals(V));System.out.println("U^sk_i = V
  // is...... "+checks);
  // NizkDlEqProof prf = NizkDlEqProof.generateProof(ctx, pk_i, U, V,
  // sk_i);log.info(" dealer DLEQ ok?
  // "+NizkDlEqProof.verifyProof(ctx,pk_i,U,V,prf));
  // //

  // // 8) Publish SharingOutput
  // SharingOutput out = new SharingOutput(me, me, pk_i, Cij, CHat, prf);
  // SharingOutputDTO dto = SharingOutputDTO
  // .from(out);log.info("pk_i for PBB dealer {} =
  // (dto){}",me,dto.dealerPub);pbb.publish("DealerPublish",dto);
  // }

  // Correct polynomial evaluation method
  public static BigInteger evaluatePolynomial(BigInteger[] coeffs, BigInteger x, BigInteger p) {
    BigInteger result = coeffs[coeffs.length - 1];
    for (int i = coeffs.length - 2; i >= 0; i--) {
      result = result.multiply(x).add(coeffs[i]).mod(p);
    }
    return result;
  }

}
