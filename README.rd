Magnus Mølgaard Andersen
MSc Software Design

# NAP-DKG (Java) – Reproducible Implementation

This repository contains a Java implementation of the **optimistic version of NAP-DKG
(Network-Agnostic Dynamic Proactive Distributed Key Generation)**.

The project was developed as part of an MSc thesis in Software Design and focuses on
**distributed cryptography, protocol implementation, and applied IT security**.
The implementation is inspired by **DHPVSS** constructions and the **YOLO-YOSO**
(You Only Speak Once) communication approach.

The goal is not production deployment, but **reproducibility, clarity, and measurement**
of runtime and communication overhead under different network conditions.

---

## Overview

- Java 17 implementation of optimistic NAP-DKG  
- Elliptic-curve cryptography (secp256r1)  
- Public verifiability using non-interactive DLEQ proofs  
- SCRAPE-style consistency checks  
- Simulated Public Bulletin Board (HTTP)  
- Benchmarking of runtime and communication cost  
- Optional network latency and jitter simulation  

---

## Prerequisites

- Java 17 JDK  
- Gradle 8.x  
- Node.js (for JSON server)

---

## Running the protocol

### Clone and start bulletin board
```bash

- git clone https://github.com/classmande/NAP-DKG-in-java.git
- cd to folder containing "app"
- npx json-server --watch db.json --port 3003

- Open new terminal
In a new terminal, COPY/PASTE this:
./gradlew run --args="--n 10 --t 5 --fa 1" 
  
Run app/src/main/java/org/example/napdkg/cli/FullTest.java for 
quick benchmark with N = 10 
(Simulating a simple speed test of the whole protocol with (no jitter/latency) all Participants using Javas Threads 
(allows a program to operate more efficiently by doing multiple things at the same time)).


RUNNING WITH LATENCY AND JITTER: 
- go to app/src/main/java/org/example/napdkg/cli/FullTest.java
- adjust the following lines in runOnce method:
  final long seed = propLong("dkg.seed", 0L);
        final long L = propLong("net.latencyMs", 0L);
        final double J = propDouble("net.jitterPct", 0);


- run again with:
./gradlew run --args="--n 10 --t 5 --fa 1" 
