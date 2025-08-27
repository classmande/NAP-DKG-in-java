package org.example.napdkg.cli;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.example.napdkg.client.GsonFactory;
import org.example.napdkg.client.HttpPbbClient;
import org.example.napdkg.client.InMemoryPbbClient;
import org.example.napdkg.client.InstrumentedPbbClient;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.client.TopicPoller;
import org.example.napdkg.core.DHPVSS_Setup;
import org.example.napdkg.core.NetShimPbb;
import org.example.napdkg.core.NizkDlProof;
import org.example.napdkg.core.PartyContext;
import org.example.napdkg.core.Phase;
import org.example.napdkg.core.PhaseScope;
import org.example.napdkg.core.PublicKeysWithProofs;
import org.example.napdkg.core.SetupPhasePublisher;
import org.example.napdkg.core.ShareVerificationPublish;
import org.example.napdkg.core.SharingOutput;
import org.example.napdkg.core.SharingPhase;
import org.example.napdkg.core.VerificationPhase;
import org.example.napdkg.dto.EphemeralKeyDTO;
import org.example.napdkg.dto.ShareVerificationOutputDTO;
import org.example.napdkg.dto.SharingOutputDTO;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.GroupGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;

public class FullTest {

    // Iterations, number of participants, threshold and fa(secure parameter)
    private static final int NUM_ITERATIONS = 1;
    private static final int n = 10;
    private static final int t = n / 2 + 1;
    private static final int fa = 1;

    private static class TimingResult {
        double setupMs, sharingMs, verificationMs, thresholdMs, totalMs;
    }

    public static TimingResult runOnce(PbbClient raw) throws Exception {
        // Logger for debugging, info and warning statements.
        Logger log = LoggerFactory.getLogger(FullTest.class);

        // Gson to convert Java Objects into JSON and vice versa
        Gson gson = GsonFactory.createGson();
        // 1) Global timer
        long startAll = System.nanoTime();

        InstrumentedPbbClient base = new InstrumentedPbbClient(raw, gson);

        long L = Long.getLong("net.latencyMs", 10L);
        double J = Double.parseDouble(System.getProperty("net.jitterPct", "2.0"));
        PbbClient pbb = new NetShimPbb(base, L, J);
        // // // 2) Build PBB client (public ledger) (instrumented)????? Whats
        // instrumented
        // // // ?????

        // 3) DKG context
        // Groupgeneration
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        // Setup
        DkgContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);
        // 4) Executor with at most n threads (and no more than CPU cores)
        // For threads to run the participants asynchronously.
        ExecutorService executor = Executors.newFixedThreadPool(n);
        // For timing
        TimingResult result = new TimingResult();
        // —— Parallel clear old data ——
        List<Callable<Void>> clearTasks = new ArrayList<>();
        clearTasks.add(() -> {
            for (EphemeralKeyDTO e : pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class))
                pbb.delete("ephemeralKeys", e.id);
            return null;
        });
        clearTasks.add(() -> {
            for (SharingOutputDTO sh : pbb.fetch("DealerPublish", SharingOutputDTO.class))
                pbb.delete("DealerPublish", sh.id);
            return null;
        });
        clearTasks.add(() -> {
            for (ShareVerificationOutputDTO so : pbb.fetch("ShareVerificationOutput", ShareVerificationOutputDTO.class))
                pbb.delete("ShareVerificationOutput", so.id);
            return null;
        });
        executor.invokeAll(clearTasks);
        // 5) Create PartyContexts
        List<PartyContext> parties = new ArrayList<>(n);
        for (int i = 0; i < n; i++)
            parties.add(new PartyContext(i, ctx, pbb, n, t, fa));

        // —— Phase 1: Setup —— Splittet in publishEphemeralKey and
        // awayAllEpehemeralKeys

        long t0 = System.nanoTime();
        List<Callable<Void>> tasks = new ArrayList<>();
        try (TopicPoller<EphemeralKeyDTO> ekPoller = new TopicPoller<>(pbb, "ephemeralKeys", EphemeralKeyDTO.class,
                dto -> dto.id, 50)) {

            ekPoller.start();

            // --- Phase 1: publish keys (unchanged) ---

            for (PartyContext P : parties)
                tasks.add(() -> {
                    SetupPhasePublisher.publishEphemeralKey(P);
                    return null;
                });
            executor.invokeAll(tasks);

            // --- Phase 1.2: wait & verify, but use the poller snapshot, not N×fetch ---
            List<Callable<Void>> waits = new ArrayList<>();
            for (PartyContext P : parties) {
                waits.add(() -> {
                    // wait until we have all n keys in the cache
                    ekPoller.awaitAtLeast(n, 10_000);

                    // decode/verify exactly like your SetupPhaseWaiter, but from snapshot()
                    List<EphemeralKeyDTO> dtos = ekPoller.snapshot();
                    for (EphemeralKeyDTO dto : dtos) {
                        byte[] raws = org.bouncycastle.util.encoders.Hex.decode(dto.publicKey);
                        var Q = P.ctx.getGenerator().getCurve().decodePoint(raws).normalize();
                        String[] parts = dto.schnorrProof.split("\\|");
                        var prf = new NizkDlProof(
                                new java.math.BigInteger(parts[0], 16),
                                new java.math.BigInteger(parts[1], 16));

                        P.allEphPubs[dto.partyIndex] = new PublicKeysWithProofs(dto.partyIndex, Q, prf);
                        if (!NizkDlProof.verifyProof(P.ctx, Q, prf))
                            throw new IllegalStateException("pk check failed - abort");
                    }
                    return null;
                });
            }
            executor.invokeAll(waits);
        }
        result.setupMs = (System.nanoTime() - t0) / 1_000_000.0;

        // —— Phase 2: Sharing —— //Every party Pi for i →[n]
        t0 = System.nanoTime();
        tasks.clear();
        tasks = new ArrayList<>();
        try (PhaseScope ignored = new PhaseScope(Phase.SHARING)) {
            // Lambda/arrow function. This is a little function that will run later. So the
            // add is a callable void that will be added to tasks.
            // Here we add an instance a SharingPhase with P and t and
            // dorunSharingAsDealer2() for that party P. And that is done for each party P
            // in parties.
            for (PartyContext P : parties)
                tasks.add(() -> {
                    new SharingPhase(P, t).runSharingAsDealer2();
                    return null;
                });
            executor.invokeAll(tasks);
            result.sharingMs = (System.nanoTime() - t0) / 1_000_000.0;
            // Timing Ends for Setup phase
        }

        // --- Phase 3: Verification (stop at t+fa) ---
        t0 = System.nanoTime();
        tasks = new ArrayList<>();

        System.out.println("==> Verification");

        // Start a single background poller for DealerPublish
        try (TopicPoller<SharingOutputDTO> dpPoller = new TopicPoller<>(pbb, "DealerPublish", SharingOutputDTO.class,
                dto -> dto.id, 25)) {

            dpPoller.start();
            VerificationPhase.setDealerPoller(dpPoller);

            // Build vps, passing the poller in
            List<VerificationPhase> vps = new ArrayList<>(n);
            for (PartyContext P : parties)
                vps.add(new VerificationPhase(P)); // <— new ctor

            final int target = t + fa;

            for (int i = 0; i < n; i++) {
                final int idx = i;
                tasks.add(() -> {
                    VerificationPhase vp = vps.get(idx);

                    for (int d = 0; d < n && vp.q1Size() < target; d++) {
                        boolean already = false;
                        for (SharingOutput sh : vp.getQ1()) {
                            if (sh.getDealerIndex() == d) {
                                already = true;
                                break;
                            }
                        }
                        if (already)
                            continue;

                        try {
                            vp.VerifySharesFor(d);
                        } catch (Exception e) {
                            log.warn("Party {}: VerifySharesFor({}) failed: {}", idx, d, e.toString());
                        }
                    }

                    vp.finalizeQ1Deterministically();
                    List<Integer> dealers = new ArrayList<>();
                    for (SharingOutput sh : vp.getQ1())
                        dealers.add(sh.getDealerIndex());
                    log.info("Party {} finalized Q1 size={} dealers={}", idx, vp.q1Size(), dealers);
                    return null;
                });
            }

            executor.invokeAll(tasks);
            result.verificationMs = (System.nanoTime() - t0) / 1_000_000.0;

            // Wait and surface errors

            // —— Phase 4: Threshold + Reconstruction ——
            // —— Phase 4a: publish Θ_i (threshold outputs) ——
            // Step 1-4 in Threshold Key Computation
            t0 = System.nanoTime();

            // not quite sure with the final int idx.
            // however we use the verificationPhase instance vps to run the threshold
            // functions on.
            for (int i = 0; i < n; i++) {
                final int idx = i;
                tasks.add(() -> {
                    vps.get(idx).publishThresholdOutput(); // <-- REUSE the same vp instance
                    return null;
                });
            }
            var futsA = executor.invokeAll(tasks); // execute
            for (var f : futsA)
                f.get(); // surface errors instead of silently hanging - for debugging if the system just
                         // hangs in deadlock.

            System.out.println("<== THRESHOLD publish");

            // —— Phase 4b: collect Θ_j (Q2), prune, and final reconstruction ——
            // step 5 create the Q2 by collecting the parties that published their
            // verification to PBB. using CllectAndPruneThresholdOutputs().
            // step 6 computing Wj and dropping parties if DLEQ doesen't approve also in
            // CollectAndPruneThresholdOutputs().
            tasks.clear();
            for (int i = 0; i < n; i++) {
                final int idx = i;
                tasks.add(() -> {
                    VerificationPhase vp = vps.get(idx); // reuse again
                    List<ShareVerificationPublish> Q2 = vp.collectAndPruneThresholdOutputs();
                    // step 7 computing tpk by reconstructing with GShamirSharing and comparing all
                    // tpks to the first one that finished the tpk.
                    vp.finalReconstruction(vp.getQ1(), Q2);
                    return null;
                });
            }
            executor.invokeAll(tasks);

            result.thresholdMs = (System.nanoTime() - t0) / 1_000_000.0;

            // 6) Total time
            long endAll = System.nanoTime();
            result.totalMs = (endAll - startAll) / 1_000_000.0;
            // poller auto-stops here
        } finally {
            // ensure we clear the static pointer
            VerificationPhase.setDealerPoller(null);
            executor.shutdown();
        }

        // executor.shutdown();
        executor.awaitTermination(1, TimeUnit.MINUTES);
        System.out.println(base.prettySummary()); // or whatever your InstrumentedPbbClient exposes
        return result;

    }

    public static void main(String[] args) throws Exception {
        // Flag “inmem” for in-memory PBB
        boolean inmem = args.length > 0 && args[0].equalsIgnoreCase("inmem");

        PbbClient raw = inmem ? new InMemoryPbbClient() : new HttpPbbClient("http://127.0.0.1:3003");

        List<TimingResult> results = new ArrayList<>(NUM_ITERATIONS);
        System.out.printf("Running %d iterations (%s mode)…%n%n", NUM_ITERATIONS, inmem ? "in-memory" : "HTTP");
        for (int i = 1; i <= NUM_ITERATIONS; i++) {
            System.out.printf("=== Iteration %d/%d ===%n", i, NUM_ITERATIONS);
            TimingResult tr = runOnce(raw);
            results.add(tr);
            System.out.printf(
                    "Setup: %8.3f ms | Sharing: %8.3f ms | Verification: %8.3f ms | Threshold: %8.3f ms | Total: %8.3f ms%n%n",
                    tr.setupMs, tr.sharingMs, tr.verificationMs, tr.thresholdMs, tr.totalMs);
        }
        // Aggregate statistics
        double[] sum = new double[5], sq = new double[5];
        for (TimingResult tr : results) {
            double[] v = { tr.setupMs, tr.sharingMs, tr.verificationMs, tr.thresholdMs, tr.totalMs };
            for (int j = 0; j < 5; j++) {
                sum[j] += v[j];
                sq[j] += v[j] * v[j];
            }
        }
        int N = results.size();
        String[] names = { "Setup", "Sharing", "Verification", "Threshold", "Total" };
        DecimalFormat df = new DecimalFormat("0.000");
        System.out.println("=== Summary (mean ± stddev) ===");
        for (int j = 0; j < 5; j++) {
            double mean = sum[j] / N;
            double var = (sq[j] - sum[j] * sum[j] / N) / (N - 1);
            System.out.printf("%-12s: %7s ms ± %7s ms%n", names[j], df.format(mean), df.format(Math.sqrt(var)));
        }
        System.out.printf("Running %d iterations (%s mode)…%n%n", NUM_ITERATIONS, inmem ? "in-memory" : "HTTP");

    }
}