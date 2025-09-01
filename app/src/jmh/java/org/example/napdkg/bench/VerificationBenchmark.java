package org.example.napdkg.bench;

import org.example.napdkg.core.PartyContext;
import org.example.napdkg.core.SharingPhase;
import org.example.napdkg.core.VerificationPhase;
import org.example.napdkg.dto.SharingOutputDTO;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Setup;

import java.util.List;

public class VerificationBenchmark {

    @Setup(Level.Invocation)
    public void prepareShares(BenchmarkState state) throws Exception {
        // Ensure there are at least (t + fa) DealerPublish outputs on the PBB, so that
        // verification can proceed.
        int needed = state.t + state.fa;
        List<SharingOutputDTO> existing = state.pbb.fetch("DealerPublish", SharingOutputDTO.class);
        if (existing.size() < needed) {
            // If not enough, force‐run the sharing phase for everyone (just like in
            // SharingBenchmark).
            for (PartyContext P : state.parties) {
                SharingPhase sp = new SharingPhase(P, state.t);
                sp.runSharingAsDealer();
            }
            // Wait until threshold reached
            List<SharingOutputDTO> all;
            do {
                Thread.sleep(100);
                all = state.pbb.fetch("DealerPublish", SharingOutputDTO.class);
            } while (all.size() < needed);
        }
    }

    @Benchmark
    public void verifyAllShares(BenchmarkState state) throws Exception {
        // For each party, run VerificationPhase.VerifySharesFor(dealerIndex) for all
        // dealers 0..n−1:
        for (PartyContext P : state.parties) {
            VerificationPhase vp = new VerificationPhase(P);
            for (int dealerIndex = 0; dealerIndex < state.n; dealerIndex++) {
                vp.VerifySharesFor(dealerIndex);
            }
        }
    }
}
