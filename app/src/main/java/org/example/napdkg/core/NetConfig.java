package org.example.napdkg.core;

// NetConfig.java
public record NetConfig(long latencyMs, double jitterPct, double kbps) {
    public static NetConfig disabled() {
        return new NetConfig(0, 0.0, 0.0);
    }
}
