package org.example.napdkg;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

public class ForcedTrueAggregatorTestR1 {
    private static final ECDomainParameters CURVE;
    static {
        var params = CustomNamedCurves.getByName("secp256r1");
        CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH(),
                params.getSeed());
    }
    private static final SecureRandom rnd = new SecureRandom();

    public static void main(String[] args) {
        // 1) Dealer ephemeral key skD
        BigInteger skD = randScalar();
        ECPoint pkD = CURVE.getG().multiply(skD).normalize();

        // 2) Participants ephemeral keys E1, E2
        BigInteger sk1 = randScalar();
        ECPoint E1 = CURVE.getG().multiply(sk1).normalize();

        BigInteger sk2 = randScalar();
        ECPoint E2 = CURVE.getG().multiply(sk2).normalize();

        // 3) Dealer picks a single "secret" rD
        // a_{D,1} = rD; a_{D,2} = rD;
        BigInteger rD = randScalar();
        ECPoint A1 = CURVE.getG().multiply(rD).normalize();
        ECPoint A2 = CURVE.getG().multiply(rD).normalize();

        // 4) Masked shares:
        ECPoint C1 = A1.add(E1.multiply(skD)).normalize();
        ECPoint C2 = A2.add(E2.multiply(skD)).normalize();

        // 5) Aggregator polynomial forced to 1 => U = E1 + E2, V = C1 + C2
        ECPoint U = E1.add(E2).normalize();
        ECPoint V = C1.add(C2).normalize();

        // 6) Check aggregator condition: V == U * skD ?
        ECPoint check = U.multiply(skD).normalize();

        System.out.println("Curve: secp256r1");
        System.out.println("Dealer ephemeral skD  = 0x" + skD.toString(16));
        System.out.println("pkD = " + pkD);
        System.out.println("E1  = " + E1);
        System.out.println("E2  = " + E2);
        System.out.println("rD  = 0x" + rD.toString(16));
        System.out.println("A1  = " + A1);
        System.out.println("A2  = " + A2);
        System.out.println("C1  = " + C1);
        System.out.println("C2  = " + C2);
        System.out.println("U   = " + U);
        System.out.println("V   = " + V);
        System.out.println("U * skD = " + check);

        boolean aggregatorOk = check.equals(V);
        System.out.println("Aggregator check = " + aggregatorOk + " (expected false unless sum(A1,A2)=0)");
        if (!aggregatorOk) {
            System.out.println(">>> Typically false unless ∑ A_{i,j}=0 under aggregator weighting. <<<");
        }
    }

    private static BigInteger randScalar() {
        return new BigInteger(CURVE.getN().bitLength(), rnd).mod(CURVE.getN());
    }
}
