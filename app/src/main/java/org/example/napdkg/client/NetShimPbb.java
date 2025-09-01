package org.example.napdkg.client;

import java.util.List;
import java.util.Random;

public final class NetShimPbb implements PbbClient {
    private final PbbClient base;
    private final long latencyMs;
    private final double jitterPct;
    private final Random rnd = new Random();

    // observed stats
    private long pubCalls, fetchCalls, delCalls;
    private long pubDelayMs, fetchDelayMs, delDelayMs;

    public NetShimPbb(PbbClient base, long latencyMs, double jitterPct) {
        this.base = base;
        this.latencyMs = latencyMs;
        this.jitterPct = jitterPct;
    }

    private long sleepWithJitter1(long bytes) throws InterruptedException {
        double eps = (rnd.nextDouble() * 2 - 1) * (jitterPct / 100.0);
        long delay = Math.max(0L, Math.round(latencyMs * (1.0 + eps)));
        Thread.sleep(delay);
        return delay;
    }

    @Override
    public void publish(String topic, Object dto) throws Exception {
        int sz = (dto == null) ? 0
                : dto.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        long d = sleepWithJitter1(sz); // <-- get actual delay
        pubCalls++; // <-- count
        pubDelayMs += d; // <-- accumulate
        base.publish(topic, dto);
    }

    @Override
    public <T> List<T> fetch(String topic, Class<T> clazz) throws Exception {
        long d = sleepWithJitter1(0); // (no BW shaping w/o knowing payload; fine if BW=0)
        fetchCalls++;
        fetchDelayMs += d;
        return base.fetch(topic, clazz);
    }

    @Override
    public void delete(String topic, String id) throws Exception {
        long d = sleepWithJitter1(0);
        delCalls++;
        delDelayMs += d;
        base.delete(topic, id);
    }

    // expose stats
    public String latencySummary() {
        double ap = pubCalls == 0 ? 0 : (pubDelayMs * 1.0 / pubCalls);
        double af = fetchCalls == 0 ? 0 : (fetchDelayMs * 1.0 / fetchCalls);
        double ad = delCalls == 0 ? 0 : (delDelayMs * 1.0 / delCalls);
        return String.format(
                "Sim net: L=%d ms, J=%.1f%% |  avg delay (ms): publish=%.1f, fetch=%.1f, delete=%.1f",
                latencyMs, jitterPct, ap, af, ad);
    }
}
