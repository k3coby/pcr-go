# pcr-go

This is a Go implementation of the private containment retrieval (PCR) protocol
proposed in the paper "[_Using Amnesia to detect credential database breaches_](https://www.usenix.org/system/files/sec21-wang-ke-coby.pdf)" (USENIX Security '21). Currently, 
this implementation is for purpose of performance evaluation only.

### Performance Evaluation

_performance.go_ can be used to show average PCR message sizes and generation times over a specified number of runs.

Run experiments with default parameters:

```Golang
go run performance.go
```

or run experiments with specified parameters. For example,

``` Golang
go run performance.go -keyLength=256 -numHoneywords=1024 -numThreads=2 -enablePC -numRounds=50 -monitorInput="Simba"
```

Parameters:
* -keyLength=256: the key length of the underlying ECC-ElGamal is 256 bits. Other options include 224, 384, and 512. (Default: 256)
* -numHoneywords=1024: the number of honeywords (denoted by _k_ in the paper) in the target/requester/receiver's set is 1024. (Default: 1024)
* -numThreads=2: both parties run the protocol with 2 threads. (Default: 2)
* -enablePC: Point compression (specified in section 4.3.6 of ANSI X9.62) for the underlying curve is enabled. (Default: enabled)
* -numRounds=50: 50 rounds are required to produce an evaluation result. (Default: 50)
* -monitorInput="Simba": the monitor/responder/sender's input element. (Default: "Simba")

In _performance.go_, the target's input set is filled with "Simba" and some other randomly generated strings starting with "Simba" (e.g., "Simba1234") to reach the specified set size. So a containment relation holds between the target's input set and the string "Simba", as the monitor's input, while the relation does not hold for any other strings not starting with "Simba".

### Citation

```latex
@inproceedings {wang2021:amnesia,
title = {Using Amnesia to detect credential database breaches},
author = {Wang, Ke Coby and Reiter, Michael K.},
booktitle = {30\textsuperscript{th} {USENIX} Security Symposium},
publisher = {{USENIX} Association},
month = {Aug},
year = {2021}
}
```
