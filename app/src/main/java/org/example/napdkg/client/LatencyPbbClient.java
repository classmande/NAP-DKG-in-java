package org.example.napdkg.client;

import java.util.List;

public final class LatencyPbbClient implements PbbClient {
    private final PbbClient inner;
    private final long baseMs, jitterMs;

    public LatencyPbbClient(PbbClient inner, long baseMs, long jitterMs) {
        this.inner = inner;
        this.baseMs = Math.max(0, baseMs);
        this.jitterMs = Math.max(0, jitterMs);
    }

    private long drawDelay() {
        if (baseMs == 0 && jitterMs == 0)
            return 0L;
        long j = (jitterMs == 0) ? 0L
                : java.util.concurrent.ThreadLocalRandom.current().nextLong(-jitterMs, jitterMs + 1);
        return Math.max(0L, baseMs + j);
    }

    private static void nap(long ms) {
        if (ms <= 0)
            return;
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    // Simulate network on reads (polling/fetch); delay BEFORE the call
    @Override
    public <T> List<T> fetch(String r, Class<T> t) throws Exception {
        nap(drawDelay());
        return inner.fetch(r, t);
    }

    @Override
    public void publish(String r, Object o) throws Exception {
        inner.publish(r, o);
    }

    @Override
    public void delete(String r, String id) throws Exception {
        inner.delete(r, id);
    }

}
