package main

import (
	"github.com/op/go-logging"
	"github.com/xlab-si/emmy/common"
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
	//defer wg.Done()

	switch example {
	case "pedersen", "pedersen-zkp", "pedersen-zkpok":
		GenericClient(i, example, n)
		//Pedersen()
	case "pedersen_ec", "pedersen_ec-zkp", "pedersen_ec-zkpok":
		GenericClient(i, example, n)
		//PedersenEC()
	case "pedersen_ec_stream":
		//PedersenECStream()
		GenericClient(i, example, n)
	case "schnorr", "schnorr-zkp", "schnorr-zkpok":
		//protocolType := getProtocolType(example)
		//Schnorr(protocolType)
		GenericClient(i, example, n)
	case "schnorr_ec", "schnorr_ec-zkp", "schnorr_ec-zkpok":
		//protocolType := getProtocolType(example)
		//SchnorrEC(protocolType)
		GenericClient(i, example, n)
	case "cspaillier", "cspaillier-zkp", "cspaillier-zkpok":
		//dir := config.LoadKeyDirFromConfig()
		//pubKeyPath := filepath.Join(dir, "cspaillierpubkey.txt")
		//Paillier(pubKeyPath)
		GenericClient(i, example, n)
	default:
		logger.Criticalf("ERROR: Invalid example: %s", example)
	}

	//fmt.Printf("[%d] done\n", i)
}

func GenericClient(id int, schema string, n int) {
	schemaTypeVariant := strings.Split(strings.ToUpper(schema), "-")

	// Spawn the client that will execute the protocol of choice
	clientParams := &ClientParams{}
	clientParams.SchemaType = schemaTypeVariant[0]
	if len(schemaTypeVariant) > 1 {
		clientParams.SchemaVariant = schemaTypeVariant[1]
	}
	client := NewProtocolClient(clientParams)

	/* ***********************************************************************************
	//TODO Try to actually just call the same client stub from several goroutines here....
	//	... dont just create new clients
	************************************************************************************* */

	// Set the actual values that are to be used to bootstrap the protocol
	protocolParams := ProtocolParams{}
	protocolParams["commitVal"] = *big.NewInt(121212121)

	/*var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			client.ExecuteProtocol(protocolParams)
		}()
	}
	wg.Wait()*/

	client.ExecuteProtocol(protocolParams)

	return
}

func getProtocolType(name string) common.ProtocolType {
	if strings.Contains(name, "zkpok") {
		return common.ZKPOK
	} else if strings.Contains(name, "zkp") {
		return common.ZKP
	}
	return common.Sigma
}
