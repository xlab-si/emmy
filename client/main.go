package main

import (
	"github.com/op/go-logging"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var logger = logging.MustGetLogger("emmy-client")
var format = logging.MustStringFormatter(
	`%{color}%{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

func main() {
	logging.SetFormatter(format)

	if len(os.Args) < 2 {
		logger.Critical("Usage: go run examples.go [pedersen|pedersen_ec|schnorr|schnorr_ec|cspaillier]")
		return
	}

	example := os.Args[1]
	n := 1
	var err error

	if len(os.Args) <= 4 {
		n, err = strconv.Atoi(os.Args[2])
		if err != nil {
			logger.Criticalf("Could not convert '%s' to integer, running a single client process\n", os.Args[2])
			n = 1
		}
	}

	runConcurrently := false
	if len(os.Args) == 4 {
		if strings.Compare(os.Args[3], "concurrent") == 0 {
			logger.Notice("Will start clients concurrently")
			runConcurrently = true
		} else {
			logger.Notice("Will start clients sequentially")
		}
	}

	var wg sync.WaitGroup

	start := time.Now()

	for i := 0; i < n; i++ {
		logger.Infof("Running client #%d\n", i)
		if runConcurrently {
			wg.Add(1)
			go func() {
				defer wg.Done()
				runExample(example, i, n)
			}()
		} else {
			runExample(example, i, n)
		}
	}

	wg.Wait()

	elapsed := time.Since(start)
	logger.Noticef("Time: %v seconds", elapsed.Seconds())

	return
}

func runExample(example string, i int, n int) {

	client := getGenericClient(example)

	/* Placeholder for values used to bootstrap chosen protocol
	The actual (example) values will be filled in depending on which protocol we are starting */
	protocolParams := ProtocolParams{}

	switch example {
	case "pedersen", "pedersen-zkp", "pedersen-zkpok":
		protocolParams["commitVal"] = *big.NewInt(121212121)
	case "pedersen_ec", "pedersen_ec-zkp", "pedersen_ec-zkpok":
		protocolParams["commitVal"] = *big.NewInt(121212121)
	//case "schnorr", "schnorr-zkp", "schnorr-zkpok":
	//	protocolParams["secret"] = *big.NewInt(345345345334)
	//protocolParams["dlog"] = config.LoadPseudonymsysDLog()

	//protocolType := getProtocolType(example)
	//Schnorr(protocolType)

	//case "schnorr_ec", "schnorr_ec-zkp", "schnorr_ec-zkpok":
	//protocolType := getProtocolType(example)
	//SchnorrEC(protocolType)
	//case "cspaillier", "cspaillier-zkp", "cspaillier-zkpok":
	//dir := config.LoadKeyDirFromConfig()
	//pubKeyPath := filepath.Join(dir, "cspaillierpubkey.txt")
	//Paillier(pubKeyPath)
	default:
		logger.Criticalf("ERROR: Invalid example: %s", example)
		return
	}

	client.ExecuteProtocol(protocolParams)
}

func getGenericClient(schema string) *Client {
	schemaTypeVariant := strings.Split(strings.ToUpper(schema), "-")

	// Spawn the client that will execute the protocol of choice
	clientParams := &ClientParams{}
	clientParams.SchemaType = schemaTypeVariant[0]
	if len(schemaTypeVariant) > 1 {
		clientParams.SchemaVariant = schemaTypeVariant[1]
	}
	client := NewProtocolClient(clientParams)
	return client
}
