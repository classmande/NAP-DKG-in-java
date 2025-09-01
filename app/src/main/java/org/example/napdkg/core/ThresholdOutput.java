
package org.example.napdkg.core;

import org.bouncycastle.math.ec.ECPoint;

public class ThresholdOutput {
    public final int dealerIndex;
    public final int partyIndex;
    public final ECPoint tpki;
    public final NizkDlEqProof proof;

    public ThresholdOutput(int dealerIndex,
            int partyIndex,
            ECPoint tpki,
            NizkDlEqProof proof) {
        this.dealerIndex = dealerIndex;
        this.partyIndex = partyIndex;
        this.tpki = tpki;
        this.proof = proof;
    }
}
