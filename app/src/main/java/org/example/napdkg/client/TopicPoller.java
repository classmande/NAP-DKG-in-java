package org.example.napdkg.client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

public class TopicPoller<T> implements AutoCloseable {
    private final PbbClient pbb;
    private String topic = "";
    private final Class<T> clazz;
    private final Function<T, String> idFn;
    private final long pollMs;

    private final ConcurrentMap<String, T> cache = new ConcurrentHashMap<>();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final ScheduledExecutorService ses = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "TopicPoller-" + topic);
        t.setDaemon(true);
        return t;
    });

    public TopicPoller(PbbClient pbb, String topic, Class<T> clazz,
            Function<T, String> idFn, long pollMs) {
        this.pbb = Objects.requireNonNull(pbb);
        this.topic = Objects.requireNonNull(topic);
        this.clazz = Objects.requireNonNull(clazz);
        this.idFn = Objects.requireNonNull(idFn);
        this.pollMs = pollMs;
    }

    public void start() {
        if (running.compareAndSet(false, true)) {
            ses.scheduleWithFixedDelay(this::tick, 0, pollMs, TimeUnit.MILLISECONDS);
        }
    }

    private void tick() {
        if (!running.get())
            return;
        try {
            List<T> items = pbb.fetch(topic, clazz);
            for (T it : items) {
                String id = idFn.apply(it);
                if (id != null)
                    cache.putIfAbsent(id, it);
            }
        } catch (Exception e) {
            // swallow and try again later
        }
    }

    /** Immutable snapshot of all items seen so far. */
    public List<T> snapshot() {
        return Collections.unmodifiableList(new ArrayList<>(cache.values()));
    }

    /** Current number of distinct items. */
    public int size() {
        return cache.size();
    }

    /** Block until at least k items are cached (or timeout). */
    public boolean awaitAtLeast(int k, long timeoutMs) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        while (size() < k) {
            long left = deadline - System.nanoTime();
            if (left <= 0)
                return false;
            Thread.sleep(Math.min(50, TimeUnit.NANOSECONDS.toMillis(left)));
        }
        return true;
    }

    public void stop() {
        running.set(false);
        ses.shutdownNow();
    }

    @Override
    public void close() {
        stop();
    }
}
