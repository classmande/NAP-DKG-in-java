package org.example.napdkg.core;

// Metrics.java
import java.util.EnumMap;
import java.util.concurrent.atomic.LongAdder;

public final class Metrics {
    public static final class Stat {
        public final LongAdder bytesIn = new LongAdder();
        public final LongAdder bytesOut = new LongAdder();
        public final LongAdder msgsIn = new LongAdder();
        public final LongAdder msgsOut = new LongAdder();
    }

    private final EnumMap<Phase, Stat> byPhase = new EnumMap<>(Phase.class);

    public Metrics() {
        for (Phase p : Phase.values())
            byPhase.put(p, new Stat());
    }

    private Stat stat() {
        Phase p = PhaseScope.current();
        return byPhase.get(p == null ? Phase.OTHER : p);
    }

    public void addOut(long bytes, long msgs) {
        Stat s = stat();
        s.bytesOut.add(bytes);
        s.msgsOut.add(msgs);
    }

    public void addIn(long bytes, long msgs) {
        Stat s = stat();
        s.bytesIn.add(bytes);
        s.msgsIn.add(msgs);
    }

    public EnumMap<Phase, Stat> snapshot() {
        return new EnumMap<>(byPhase);
    }

    /** Optional convenience so you can write Metrics m = Metrics.zero(); */
    public static Metrics zero() {
        return new Metrics();
    }
}
