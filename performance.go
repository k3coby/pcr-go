package main

import (
	"flag"
	"fmt"
	"math/rand"
	"pcr-go/pcr"
	"pcr-go/util"
	"runtime"
	"strconv"
	"time"
)

func main() {
	var params, setSize, numWorkers int
	var pointCompression bool
	var pwd2check string
	var maxRounds int

	var allKeyGenTime, allQueryGenTime, allResponseGenTime, allResponseRevealTime []int64
	var allQuerySize, allResponseSize []int

	paramPtr := flag.Int("keyLength", 256, "224, 256, 384 or 512")
	numHwPtr := flag.Int("numHoneywords", 1024, "an int")
	numWorkerPtr := flag.Int("numThreads", 2, "an int")
	pointCompressionPtr := flag.Bool("enablePC", true, "true or false")
	roundsPtr := flag.Int("numRounds", 50, "an int")
	pwd2checkPtr := flag.String("monitorInput", "Simba", "a string")

	flag.Parse()

	params = *paramPtr
	setSize = *numHwPtr + 1
	numWorkers = *numWorkerPtr
	pointCompression = *pointCompressionPtr
	pwd2check = *pwd2checkPtr
	maxRounds = *roundsPtr

	if runtime.NumCPU() > numWorkers {
		runtime.GOMAXPROCS(numWorkers)
	} else {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	fmt.Printf("\n==== Experiment Parameters ========\n[OS] # of threads >>> %d/%d\n", numWorkers, runtime.NumCPU())
	fmt.Println("[ECC-ElGamal] key length (bits) >>>", params)
	fmt.Println("[ECC-ElGamal] Point compression >>>", pointCompression)
	fmt.Printf("[Target] Set size >>> %d + 1\n", *numHwPtr)
	fmt.Println("[CF] Cuckoo filter fingerprint length >>>", 224)
	fmt.Println("[CF] Cuckoo filter bucket size >>>", 4)

	for i := 0; i < maxRounds; i++ {
		reqSet := make([]string, setSize) // the target initializes an empty set
		reqSet[0] = "Simba" // adding "Simba" as the correct password
		for i := 1; i < setSize; i++ {
			reqSet[i] = "Simba" + strconv.Itoa(rand.Intn(9999)) // adding generated variants to fill the set.
			/* Note: this is not a process to generate honeywords; it's for following performance evaluation only. */
		}
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(reqSet), func(i, j int) { reqSet[i], reqSet[j] = reqSet[j], reqSet[i] }) // shuffling the set randomly

		////////////////////////////////////////////////////////

		time0 := util.MakeTimestamp()

		pk, sk := pcr.ReqInit(params, pointCompression) // the target generates a key pair

		time1 := util.MakeTimestamp()

		queryMessage := pcr.ReqQueryGen(pk, reqSet, numWorkers) // the target/requester generates a PCR query
		queryMessageBytes := pcr.EncodeQuery(queryMessage) // the target encodes the PCR query to bytes
		queryMessageSize := len(queryMessageBytes) // get the PCR query message size in bytes

		time2 := util.MakeTimestamp()

		rcvdQueryMessage := pcr.DecodeQuery(queryMessageBytes) // the monitor/responder decodes a received PCR query
		responseMessage := pcr.RespResponseGen(rcvdQueryMessage, []byte(pwd2check), numWorkers) // the monitor/responder generates a PCR response
		responseMessageBytes := pcr.EncodeResponse(responseMessage) // the monitor/responder encodes the PCR response to bytes
		responseMessageSize := len(responseMessageBytes) // get the PCR response message size in bytes

		time3 := util.MakeTimestamp()

		rcvdResponseMessage := pcr.DecodeResponse(responseMessageBytes) // the target/requester decodes a received PCR response
		result := pcr.ReqResponseRetrieve(pk, sk, rcvdResponseMessage, reqSet, numWorkers) // the target/requester reveals the response

		time4 := util.MakeTimestamp()

		////////////////////////////////////////////////////////

		keyGenTime := time1 - time0
		queryGenTime := time2 - time1
		responseGenTime := time3 - time2
		responseRevealTime := time4 - time3

		revealRes := ""
		if result != "" {
			revealRes = "Positive: " + result
		} else {
			revealRes = "Negative"
		}

		// Report the revealing result for only the last run
		if i == maxRounds - 1 {
			fmt.Println("[PCR] PCR result >>>", revealRes)
		}

		allKeyGenTime = append(allKeyGenTime, keyGenTime)
		allQueryGenTime = append(allQueryGenTime, queryGenTime)
		allResponseGenTime = append(allResponseGenTime, responseGenTime)
		allResponseRevealTime = append(allResponseRevealTime, responseRevealTime)
		allQuerySize = append(allQuerySize, int(queryMessageSize))
		allResponseSize = append(allResponseSize, int(responseMessageSize))
		}

		fmt.Printf("==== Mean over %d repeated experiments ===\n", maxRounds)
		fmt.Printf("[Target] queryGen() takes %.2f ms\n", float32(util.GetAvgInt64(allQueryGenTime))/1000.0)
		fmt.Printf("[Target] Query message size >>> %.2f KB\n", float32(util.GetAvgInt(allQuerySize))/1000.0)
		fmt.Printf("[Monitor] responseGen() takes %.2f ms\n", float32(util.GetAvgInt64(allResponseGenTime))/1000.0)
		fmt.Printf("[Monitor] Response message size >>> %.2f KB\n", float32(util.GetAvgInt(allResponseSize)) / 1000.0)
		fmt.Printf("[Target] responseReveal() takes %.2f ms\n", float32(util.GetAvgInt64(allResponseRevealTime))/1000.0)
	}