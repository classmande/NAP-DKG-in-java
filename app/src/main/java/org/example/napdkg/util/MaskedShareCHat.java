package org.example.napdkg.util;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public final class MaskedShareCHat {
  private static final String HASH_ALGO = "SHA-256";
  private static final int BYTES = 32;

  public static BigInteger maskShare(ECPoint A, BigInteger share, BigInteger order) {
    byte[] H = hashCompressed(A); // 32B
    byte[] a = toFixed32(share); // 32B
    return new BigInteger(1, xor32(a, H));
  }

  public static BigInteger unmaskShare(ECPoint A, BigInteger cHat, BigInteger order) {
    byte[] H = hashCompressed(A); // 32B
    byte[] c = toFixed32(cHat); // 32B
    byte[] a = xor32(c, H); // 32B
    return new BigInteger(1, a); // no mod here
  }

  private static byte[] hashCompressed(ECPoint P) {
    try {
      var md = java.security.MessageDigest.getInstance(HASH_ALGO);
      return md.digest(P.normalize().getEncoded(true)); // compressed 33B -> 32B hash
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] toFixed32(BigInteger x) {
    byte[] raw = x.toByteArray(); // 2’s complement
    byte[] out = new byte[BYTES];
    int copy = Math.min(raw.length, BYTES);
    System.arraycopy(raw, raw.length - copy, out, BYTES - copy, copy);
    return out;
  }

  private static byte[] xor32(byte[] a, byte[] b) {
    byte[] out = new byte[BYTES];
    for (int i = 0; i < BYTES; i++)
      out[i] = (byte) (a[i] ^ b[i]);
    return out;
  }
}

// private static final String HASH_ALGO = "SHA-256";

// /** Dealer side: mask a₍i,j₎ into Ć₍i,j₎ = a ⊕ H′(A). */
// public static BigInteger maskShare(ECPoint A, BigInteger share, BigInteger
// order) {
// BigInteger h = hashPointToScalar(A, order);
// return share.xor(h);
// }

// /** Verifier side: recover a₍i,j₎ = Ć ⊕ H′(A). */
// public static BigInteger unmaskShare(ECPoint A, BigInteger cHat, BigInteger
// order) {
// BigInteger h = hashPointToScalar(A, order);
// return cHat.xor(h);
// }

// // in MaskedShareCHat:

// /** Hashes the *compressed* encoding of A into a scalar mod order. */
// private static BigInteger hashPointToScalar(ECPoint P, BigInteger order) {
// try {
// // 1) canonical, compressed form (33 bytes on secp256k1 / P-256)
// byte[] enc = P.normalize().getEncoded(true);
// // 2) SHA-256
// MessageDigest md = MessageDigest.getInstance(HASH_ALGO);
// byte[] digest = md.digest(enc);
// // 3) reduce into [0,order)
// return new BigInteger(1, digest).mod(order);
// } catch (NoSuchAlgorithmException e) {
// throw new RuntimeException(e);
// }
// }
// }
