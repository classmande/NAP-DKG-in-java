package org.example.napdkg.client;

import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.example.napdkg.core.Metrics;

import com.google.gson.Gson;

/** Wraps any PbbClient and counts bytes/messages globally and per topic. */
public class InstrumentedPbbClient implements PbbClient {
    private final PbbClient delegate;
    private final Gson gson;

    // ---- global counters (simple synchronized bumps) ----
    private long bytesSent = 0, bytesReceived = 0;
    private long publishes = 0, fetches = 0, deletes = 0;
    private final Metrics metrics;

    // ---- per-topic stats ----
    private static final class TopicStats {
        long pub, fetch, del, upBytes, downBytes;

        synchronized void addPublish(long up) {
            pub++;
            upBytes += up;
        }

        synchronized void addFetch(long down) {
            fetch++;
            downBytes += down;
        }

        synchronized void addDelete() {
            del++;
        }
    }

    // InstrumentedPbbClient.java
    public void resetCounters() {
        this.bytesSent = 0;
        this.bytesReceived = 0;
        this.publishes = 0;
        this.fetches = 0;
        this.deletes = 0;

    }

    private final Map<String, TopicStats> byTopic = new ConcurrentHashMap<>();

    public InstrumentedPbbClient(PbbClient delegate, Gson gson) {
        this.delegate = delegate;
        this.gson = gson;
        this.metrics = null;
    }

    public InstrumentedPbbClient(PbbClient delegate, Gson gson, Metrics metrics) {
        this.delegate = delegate;
        this.gson = gson;
        this.metrics = metrics;
    }

    private TopicStats statsFor(String topic) {
        return byTopic.computeIfAbsent(topic, __ -> new TopicStats());
    }

    // ---------------- PbbClient ----------------

    @Override
    public void publish(String topic, Object msg) throws Exception {
        byte[] data = gson.toJson(msg).getBytes(StandardCharsets.UTF_8);
        synchronized (this) {
            publishes++;
            bytesSent += data.length;
        }
        statsFor(topic).addPublish(data.length);
        delegate.publish(topic, msg);
    }

    @Override
    public void publishAll(String topic, Object[] msgs) throws Exception {
        for (Object m : msgs)
            publish(topic, m);
    }

    @Override
    public <T> List<T> fetch(String topic, Class<T> clazz) throws Exception {
        List<T> out = delegate.fetch(topic, clazz);
        String json = gson.toJson(out);
        int down = json.getBytes(StandardCharsets.UTF_8).length;
        synchronized (this) {
            fetches++;
            bytesReceived += down;
        }
        statsFor(topic).addFetch(down);
        return out;
    }

    @Override
    public void delete(String topic, String id) throws Exception {
        synchronized (this) {
            deletes++;
        }
        statsFor(topic).addDelete();
        delegate.delete(topic, id);
    }

    // ---------------- accessors & summary ----------------

    public synchronized long getBytesSent() {
        return bytesSent;
    }

    public synchronized long getBytesReceived() {
        return bytesReceived;
    }

    public synchronized long getPublishes() {
        return publishes;
    }

    public synchronized long getFetches() {
        return fetches;
    }

    public synchronized long getDeletes() {
        return deletes;
    }

    private static String human(long bytes) {
        if (bytes < 1024)
            return bytes + " B";
        double kb = bytes / 1024.0;
        if (kb < 1024)
            return new DecimalFormat("#,##0.##").format(kb) + " KB";
        double mb = kb / 1024.0;
        return new DecimalFormat("#,##0.##").format(mb) + " MB";
    }

    public String prettySummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== PBB comms ===\n");
        long up, down, pub, fet, del;
        synchronized (this) {
            up = bytesSent;
            down = bytesReceived;
            pub = publishes;
            fet = fetches;
            del = deletes;
        }
        sb.append(String.format("Publishes: %d | Fetches: %d | Deletes: %d%n", pub, fet, del));
        sb.append(String.format("Up: %s | Down: %s%n", human(up), human(down)));

        sb.append("\nPer-topic:\n");
        sb.append(String.format("%-24s %8s %8s %8s %12s %12s%n",
                "topic", "pub", "fetch", "del", "up", "down"));

        byTopic.entrySet().stream()
                .sorted(Comparator.comparing(Map.Entry::getKey))
                .forEach(e -> {
                    String topic = e.getKey();
                    TopicStats s = e.getValue();
                    long p, f, d, u, dn;
                    synchronized (s) {
                        p = s.pub;
                        f = s.fetch;
                        d = s.del;
                        u = s.upBytes;
                        dn = s.downBytes;
                    }
                    sb.append(String.format("%-24s %8d %8d %8d %12s %12s%n",
                            topic, p, f, d, human(u), human(dn)));
                });

        // quick useful ratios
        double avgUpPerPub = pub == 0 ? 0.0 : (double) up / pub;
        double avgDnPerFetch = fet == 0 ? 0.0 : (double) down / fet;
        sb.append(String.format("%nAvg up / publish: %.1f B | Avg down / fetch: %.1f B%n",
                avgUpPerPub, avgDnPerFetch));

        return sb.toString();
    }
}
