package org.example.napdkg.bench;

import java.util.List;

import org.example.napdkg.core.PartyContext;
import org.example.napdkg.core.SharingPhase;
import org.openjdk.jmh.annotations.Benchmark;

public class SharingBenchmark {

    @Benchmark
    public void generateAndPublishShares(BenchmarkState state) throws Exception {
        List<PartyContext> parties = state.parties;
        int n = state.n;
        int t = state.t;

        // (A) Clear any old “DealerPublish” entries on the PBB
        for (var each : state.pbb.fetch("DealerPublish",
                org.example.napdkg.dto.SharingOutputDTO.class)) {
            state.pbb.delete("DealerPublish", each.id);
        }

        // (B) Now, each party runs runSharingAsDealer()
        for (var P : parties) {
            var sp = new SharingPhase(P, t);
            sp.runSharingAsDealer();
        }

        // (C) Block until at least (t+fa) DealerPublish messages appear
        List<?> shares;
        do {
            Thread.sleep(200);
            shares = state.pbb.fetch("DealerPublish",
                    org.example.napdkg.dto.SharingOutputDTO.class);
        } while (shares.size() < (state.t + state.fa));
    }
}
