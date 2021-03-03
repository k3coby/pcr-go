package pcr

import (
	"compress/gzip"
	"encoding/json"
	"math/big"

	"pcr-go/cuckoofilter"
	"pcr-go/elgamal"
	"sync"
	// "time"
	"bytes"
	"io/ioutil"
)

type QueryMessage struct {
	PK *elgamal.PublicKey
	ECF [][]*elgamal.CiphertextByte
}

type ResponseMessage struct {
	ResponseBoolByte []*elgamal.CiphertextByte
	ResponseRetrievalByte []*elgamal.CiphertextByte
}

var reqGen sync.WaitGroup
var respGen sync.WaitGroup
var reqDec sync.WaitGroup

// Requester(Target) generates and ElGamal key pair
func ReqInit(params int, pointCompression bool) (*elgamal.PublicKey, *elgamal.SecretKey) {
	pk, sk := elgamal.KeyGen(params, pointCompression)
	return pk, sk
}

// This function returns a (target/requester/receiver) PCR query, given a public key,
// the input set, and the number of threads to use
func ReqQueryGen(pk *elgamal.PublicKey, reqSet []string, numWorkers int) *QueryMessage {

	encodedCF := filterGen(reqSet)
	encryptedCFByte := make([][]*elgamal.CiphertextByte, len(encodedCF))
	for i := range encryptedCFByte {
		encryptedCFByte[i] = make([]*elgamal.CiphertextByte, len(encodedCF[0]))
	}

	chWorker := make(chan int, numWorkers)
	defer close(chWorker)

	for i := range encodedCF {
		for j := range encodedCF[0] {
			chWorker <- 1
			reqGen.Add(1)
			go func(j int) {
				defer reqGen.Done()
				encryptedCFByte[i][j] = pk.Ciphertext2Bytes(pk.Encrypt(encodedCF[i][j]), pk.PointCompression)
				<- chWorker
			}(j)
		}
		reqGen.Wait()
	}

	queryMessage := &QueryMessage{
		PK:               pk,
		ECF:              encryptedCFByte,
	}

	return queryMessage
}


// This function returns a (monitor/responder/sender) PCR response, given a PCR query,
// an input string (e.g. an incorrect password) to check, and the number of threads to use.
func RespResponseGen(rcvdQueryMessage *QueryMessage, pwd2check []byte, numWorkers int) *ResponseMessage {

	respCT := make([]*elgamal.Ciphertext, 2*len(rcvdQueryMessage.ECF))
	respCTR := make([]*elgamal.Ciphertext, 2*len(rcvdQueryMessage.ECF))
	respCTByte := make([]*elgamal.CiphertextByte, 2*len(rcvdQueryMessage.ECF))
	respCTRByte := make([]*elgamal.CiphertextByte, 2*len(rcvdQueryMessage.ECF))

	fp, i1, i2 := cuckoofilter.GetFPI1I2(pwd2check, uint(len(rcvdQueryMessage.ECF[0])))
	fp2 := cuckoofilter.GetFP2(pwd2check)

	pk := rcvdQueryMessage.PK
	pk.InitCurve()
	eipwd := pk.EncryptInv(big.NewInt(0).SetBytes(fp))
	epwd := pk.Encrypt(big.NewInt(0).SetBytes(fp2))

	chWorker := make(chan int, numWorkers)
	defer close(chWorker)

	for i := range rcvdQueryMessage.ECF {
		chWorker <- 1
		respGen.Add(1)
		go func(i int) {
			defer respGen.Done()
			currCiphertext1 := pk.Bytes2Ciphertext(rcvdQueryMessage.ECF[i][i1], pk.PointCompression)
			currCiphertext2 := pk.Bytes2Ciphertext(rcvdQueryMessage.ECF[i][i2], pk.PointCompression)
			respCT[i] = pk.Add(currCiphertext1, eipwd, false)
			respCT[i+len(rcvdQueryMessage.ECF)] = pk.Add(currCiphertext2, eipwd, false)
			<- chWorker
		}(i)
	}
	respGen.Wait()

	// rand.Seed(time.Now().UnixNano())
	// rand.Shuffle(len(respCT), func(i, j int) { respCT[i], respCT[j] = respCT[j], respCT[i] })

	for i := range respCT {
		chWorker <- 1
		respGen.Add(1)
		go func(i int) {
			defer respGen.Done()
			respCT[i] = pk.ScalarMultRandomizer(respCT[i], false)// get Z
			respCTR[i] = pk.Add(pk.ScalarMultRandomizer(respCT[i], false), epwd, false) // get Z'
			respCTByte[i] = pk.Ciphertext2Bytes(respCT[i], rcvdQueryMessage.PK.PointCompression)
			respCTRByte[i] = pk.Ciphertext2Bytes(respCTR[i], rcvdQueryMessage.PK.PointCompression)
			<- chWorker
		}(i)
	}
	respGen.Wait()
	responseMessage := &ResponseMessage{respCTByte, respCTRByte}

	return responseMessage
}


// This function returns a string as the output of the target/requester/receiver revealing a response, given a key pair,
// a response message, the input set, and the number of threads to use.
func ReqResponseRetrieve(pk *elgamal.PublicKey, sk *elgamal.SecretKey, responseMessage *ResponseMessage, set []string,
	numWorkers int) string {

	var FPs [][]byte
	//res := "-1"
	for i := range set {
		FPs = append(FPs, cuckoofilter.GetFP2([]byte(set[i])))
	}

	chWorker := make(chan int, numWorkers)
	chResIndex := make(chan int, len(responseMessage.ResponseBoolByte))
	chRes := make(chan string, len(responseMessage.ResponseBoolByte))
	defer close(chWorker)
	defer close(chResIndex)
	defer close(chRes)

	for i := range responseMessage.ResponseBoolByte {
		if len(chResIndex) != 0 {
			break
		}
		chWorker <- 1
		reqDec.Add(1)
		go func(i int) {
			currCiphertext := pk.Bytes2Ciphertext(responseMessage.ResponseBoolByte[i], pk.PointCompression)
			if sk.DecryptAndCheck0(currCiphertext) {
				chResIndex <- i
			}
			reqDec.Done()
			<- chWorker
		}(i)
	}
	reqDec.Wait()

	if len(chResIndex) != 0 {
		positiveIndex := <- chResIndex
		targetCiphertext := pk.Bytes2Ciphertext(responseMessage.ResponseRetrievalByte[positiveIndex], pk.PointCompression)
		for j := range set {
			if len(chRes) != 0 {
				break
			}
			chWorker <- 1
			reqDec.Add(1)
			go func(j int) {
				if sk.DecryptAndCheck(targetCiphertext, FPs[j]) {
					chRes <- set[j]
				}
				reqDec.Done()
				<- chWorker
			}(j)
		}
		reqDec.Wait()
		return <- chRes
	} else {
		return ""
	}
}

/////////////////////////////////////////

// The target/requester/receiver initializes a cuckoo filter given its input
// set and the number of threads and represent the filter with big.Int type.
func filterGen(set []string) [][]*big.Int {
	//var encodedCF [][]*big.Int
	cf := cuckoofilter.InitCFilter(uint(len(set)))
	for i:=0; i < len(set); i++ {
		if !cf.Add([]byte(set[i])) {
			break
		}
	}

	encodedCF := make([][]*big.Int, cuckoofilter.BUCKET_SIZE)
	cfBytes := cf.Filter2Bytes()
	for i := range cfBytes {
		func(i int) {
			encodedCF[i % cuckoofilter.BUCKET_SIZE] = append(encodedCF[i % cuckoofilter.BUCKET_SIZE], big.NewInt(0).SetBytes(cfBytes[i]))
		}(i)
	}
	return encodedCF
}

////////////////

// This function encodes a query message struct into bytes.
func EncodeQuery(queryMessage *QueryMessage) []byte {

	queryMessageJson, _ := json.Marshal(*queryMessage)
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err := w.Write(queryMessageJson)
	err = w.Close()
	if err != nil {
		panic(err)
	}
	msg := []byte(b.String())

	return msg
}


// This function decodes a query message in bytes back to struct.
func DecodeQuery(queryMessageBytes []byte) *QueryMessage {

	var queryMessage QueryMessage

	r, err := gzip.NewReader(bytes.NewBuffer(queryMessageBytes))
	if err != nil {
		panic(err)
	}
	jsonQM, err := ioutil.ReadAll(r)
	err = r.Close()
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(jsonQM, &queryMessage)
	err = r.Close()
	if err != nil {
		panic(err)
	}

	return &queryMessage
}


// This function encodes a response message struct to bytes.
func EncodeResponse(responseMessage *ResponseMessage) []byte {

	responseMessageJson, _ := json.Marshal(*responseMessage)
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err := w.Write(responseMessageJson)
	err = w.Close()
	if err != nil {
		//fmt.Println("gzip error occurred!!!")
		panic(err)
	}
	msg := []byte(b.String())

	return msg
}

// This function decodes a response message in bytes to struct.
func DecodeResponse(responseMessageBytes []byte) *ResponseMessage {

	var responseMessage ResponseMessage

	r, err := gzip.NewReader(bytes.NewBuffer(responseMessageBytes))
	if err != nil {
		panic(err)
	}
	jsonRM, err := ioutil.ReadAll(r)
	err = r.Close()
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(jsonRM, &responseMessage)
	if err != nil {
		panic(err)
	}

	return &responseMessage
}