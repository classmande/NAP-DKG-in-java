package org.example.napdkg.core;

// PhaseScope.java (optional helper for try-with-resources)
public final class PhaseScope implements AutoCloseable {
    private static final ThreadLocal<Phase> TL = new ThreadLocal<>();
    private final Phase prev;

    public static Phase current() {
        return TL.get();
    }

    public PhaseScope(Phase setup) {
        prev = TL.get();
        TL.set(setup);
    }

    @Override
    public void close() {
        TL.set(prev);
    }

}