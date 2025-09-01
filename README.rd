# NAP-DKG Reproducibility

## Prerequisites
- Java 17 JDK
- Gradle 8.x

## Run everything
```bash
- git clone https://github.com/classmande/NAP-DKG-in-java.git
- cd NAP-DKG-in-java
- npx json-server --watch db.json --port 3003

- Open new terminal
In new terminal, COPY/PASTE this:
./gradlew run --args="--n 10 --t 5 --fa 1" 
  -Dorg.slf4j.simpleLogger.defaultLogLevel=info
  
Run FullTest.java for 
quick benchmark with N = 10 
(Simulating a simple speed test of the whole protocol with (no jitter/latency) all Participants using Javas Threads 
(allows a program to operate more efficiently by doing multiple things at the same time)).
