# NAP-DKG Reproducibility

## Prerequisites
- Java 17 JDK
- Gradle 8.x

## Run everything
```bash
git clone https://github.com/classmande/NAP-DKG-in-java.git
cd DHPVSS-in-java
npx json-server --watch db.json --port 3003

Run simple speed test with parameter
./gradlew run --args="--n 10 --t 5 --fa 1" 
  -Dorg.slf4j.simpleLogger.defaultLogLevel=info
  
Run QuickBench1.java for 
quick benchmark with N = 10 
(Simulating the whole protocol with all Participants Asyncronology using Javas Threads 
(allows a program to operate more efficiently by doing multiple things at the same time)).
