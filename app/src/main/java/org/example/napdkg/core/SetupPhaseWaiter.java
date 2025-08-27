// src/main/java/org/example/napdkg/core/SetupPhaseWaiter.java
package org.example.napdkg.core;

import java.math.BigInteger;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.dto.EphemeralKeyDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//For all j →[n], parse pkj as (Ej , ςj ) and check that ςj is valid w.r.t G, Ej.
//If this check fails, abort. Proceed if this check passes for all pkj : j →[n]. ie. "  if (verify == false) {
//             throw new IllegalStateException("pk check failed - abort");
//  }" //

public class SetupPhaseWaiter {
    private static final Logger log = LoggerFactory.getLogger(SetupPhaseWaiter.class);

    public static void awaitAllEphemeralKeys(PartyContext P, int n) throws Exception {
        List<EphemeralKeyDTO> dtos;
        do {
            Thread.sleep(100);
            dtos = P.pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class);
            log.info("party {} sees {} keys", P.id, dtos.size());
        } while (dtos.size() < n);

        // decode them
        for (EphemeralKeyDTO dto : dtos) {
            byte[] raw = Hex.decode(dto.publicKey);
            ECPoint Q = P.ctx.getGenerator().getCurve().decodePoint(raw).normalize();
            String[] parts = dto.schnorrProof.split("\\|");
            NizkDlProof prf = new NizkDlProof(
                    new BigInteger(parts[0], 16),
                    new BigInteger(parts[1], 16));
            P.allEphPubs[dto.partyIndex] = new PublicKeysWithProofs(dto.partyIndex, Q, prf);
            Boolean verify = NizkDlProof.verifyProof(P.ctx, P.allEphPubs[dto.partyIndex].getPublicKey(), prf);
            if (verify == false) {
                throw new IllegalStateException("pk check failed - abort");
            }
        }

    }
}
