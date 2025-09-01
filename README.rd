# NAP-DKG Reproducibility

## Prerequisites
- Java 17 JDK
- Gradle 8.x

## Run everything
```bash
- git clone https://github.com/classmande/NAP-DKG-in-java.git
- cd to folder containing "app"
- npx json-server --watch db.json --port 3003

- Open new terminal
In a new terminal, COPY/PASTE this:
./gradlew run --args="--n 10 --t 5 --fa 1" 
  
Run FullTest.java for 
quick benchmark with N = 10 
(Simulating a simple speed test of the whole protocol with (no jitter/latency) all Participants using Javas Threads 
(allows a program to operate more efficiently by doing multiple things at the same time)).


RUNNING WITH LATENCY AND JITTER: 
- go to FullTest.java
- adjust the following lines in runOnce method:
  final long seed = propLong("dkg.seed", 0L);
        final long L = propLong("net.latencyMs", 0L);
        final double J = propDouble("net.jitterPct", 0);


- run again with:
./gradlew run --args="--n 10 --t 5 --fa 1" 