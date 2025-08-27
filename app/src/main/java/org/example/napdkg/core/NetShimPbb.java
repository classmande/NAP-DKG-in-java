package org.example.napdkg.core;

import java.util.List;
import java.util.Random;

import org.example.napdkg.client.PbbClient;

public final class NetShimPbb implements PbbClient {
    private final PbbClient base;
    private final long latencyMs;
    private final double jitterPct;
    private final Random rnd = new Random();

    public NetShimPbb(PbbClient base, long latencyMs, double jitterPct) {
        this.base = base;
        this.latencyMs = Math.max(0, latencyMs);
        this.jitterPct = Math.max(0.0, jitterPct);
    }

    private void sleepWithJitter() {
        // +/- jitter% around latencyMs
        double span = latencyMs * (jitterPct / 100.0);
        long jitter = Math.round((rnd.nextDouble() * 2 - 1) * span);
        long delay = Math.max(0, latencyMs + jitter);
        try {
            Thread.sleep(delay);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    // NOTE: match interface erasure exactly
    @Override
    public void publish(String topic, Object dto) throws Exception {
        sleepWithJitter();
        base.publish(topic, dto);
    }

    @Override
    public <T> List<T> fetch(String topic, Class<T> clazz) throws Exception {
        sleepWithJitter();
        return base.fetch(topic, clazz);
    }

    @Override
    public void delete(String topic, String id) throws Exception {
        sleepWithJitter();
        base.delete(topic, id);
    }
}
