package org.example.napdkg.core;

// MetricsCsv.java
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.EnumMap;

public final class MetricsCsv {
    public static void dump(File f, RunParams rp, Metrics m, Timings tm) throws IOException {
        boolean newFile = !f.exists();
        try (var w = new BufferedWriter(new FileWriter(f, true))) {
            if (newFile) {
                w.write("n,t,fa,seed,latency_ms,jitter_pct,bw_kbps,"
                        + "setup_ms,sharing_ms,verification_ms,threshold_ms,"
                        + "bytesIn_setup,bytesOut_setup,msgsIn_setup,msgsOut_setup,"
                        + "bytesIn_sharing,bytesOut_sharing,msgsIn_sharing,msgsOut_sharing,"
                        +
                        "bytesIn_verification,bytesOut_verification,msgsIn_verification,msgsOut_verification,"
                        +
                        "bytesIn_threshold,bytesOut_threshold,msgsIn_threshold,msgsOut_threshold\n");
            }
            EnumMap<Phase, Metrics.Stat> s = m.snapshot();
            var S = s.get(Phase.SETUP);
            var H = s.get(Phase.SHARING);
            var V = s.get(Phase.VERIFICATION);
            var T = s.get(Phase.THRESHOLD);
            w.write(String.join(",",
                    String.valueOf(rp.n), String.valueOf(rp.t), String.valueOf(rp.fa),
                    String.valueOf(rp.seed),
                    String.valueOf(rp.latencyMs), String.valueOf(rp.jitterPct),
                    String.format("%.3f", tm.setupMs), String.format("%.3f", tm.sharingMs),
                    String.format("%.3f", tm.verificationMs), String.format("%.3f",
                            tm.thresholdMs),
                    String.valueOf(S.bytesIn.sum()), String.valueOf(S.bytesOut.sum()),
                    String.valueOf(S.msgsIn.sum()),
                    String.valueOf(S.msgsOut.sum()),
                    String.valueOf(H.bytesIn.sum()), String.valueOf(H.bytesOut.sum()),
                    String.valueOf(H.msgsIn.sum()),
                    String.valueOf(H.msgsOut.sum()),
                    String.valueOf(V.bytesIn.sum()), String.valueOf(V.bytesOut.sum()),
                    String.valueOf(V.msgsIn.sum()),
                    String.valueOf(V.msgsOut.sum()),
                    String.valueOf(T.bytesIn.sum()), String.valueOf(T.bytesOut.sum()),
                    String.valueOf(T.msgsIn.sum()),
                    String.valueOf(T.msgsOut.sum())));
            w.write("\n");
        }
    }

    public static final class RunParams {
        public final int n, t, fa;
        public final long seed, latencyMs;
        public final double jitterPct;

        public RunParams(int n, int t, int fa, long seed, long latencyMs, double jitterPct) {
            this.n = n;
            this.t = t;
            this.fa = fa;
            this.seed = seed;
            this.latencyMs = latencyMs;
            this.jitterPct = jitterPct;

        }
    }

    public static final class Timings {
        public final double setupMs, sharingMs, verificationMs, thresholdMs;

        public Timings(double setupMs, double sharingMs, double verificationMs,
                double thresholdMs) {
            this.setupMs = setupMs;
            this.sharingMs = sharingMs;
            this.verificationMs = verificationMs;
            this.thresholdMs = thresholdMs;
        }
    }
}
