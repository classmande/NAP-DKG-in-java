package org.example.napdkg.util;

import org.bouncycastle.math.ec.ECPoint;

public final class DkgRef {
    public static final java.util.concurrent.atomic.AtomicReference<ECPoint> TRUE_Y = new java.util.concurrent.atomic.AtomicReference<>();
    public static volatile String RUN_ID = "";

    public static void resetForNewRun() {
        TRUE_Y.set(null);
        RUN_ID = java.util.UUID.randomUUID().toString();
    }
}
