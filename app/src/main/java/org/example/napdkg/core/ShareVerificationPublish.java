// src/main/java/org/example/napdkg/core/domain/ShareVerificationOutput.java
package org.example.napdkg.core;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.dto.ShareVerificationOutputDTO;
import org.example.napdkg.util.DkgContext;

public class ShareVerificationPublish {
  public final int verifierIndex;
  public final ECPoint tpki;
  public final NizkDlEqProof Pftpki;

  public ShareVerificationPublish(
      int verifierIndex,
      ECPoint tpki,
      NizkDlEqProof Pftpki) {
    this.verifierIndex = verifierIndex;
    this.tpki = tpki;
    this.Pftpki = Pftpki;

  }

  public static ShareVerificationPublish fromDTO(ShareVerificationOutputDTO dto, DkgContext ctx) {
    // decode τ_{pk_i}
    ECPoint tpki = ctx.getGenerator()
        .getCurve()
        .decodePoint(Hex.decode(dto.tauPki))
        .normalize();

    // reconstruct proof
    BigInteger e = new BigInteger(dto.proof.getChallenge(), 16);
    BigInteger z = new BigInteger(dto.proof.getResponse(), 16);
    NizkDlEqProof proof = new NizkDlEqProof(e, z);

    return new ShareVerificationPublish(
        dto.verifierIndex,
        tpki,
        proof);
  }
}
