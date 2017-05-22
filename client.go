package main

import (
	"fmt"
	"github.com/xlab-si/emmy/common"
	//"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/examples"
	"os"
	//"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: go run examples.go [pedersen|pedersen_ec|schnorr|schnorr_ec|cspaillier]\n")
		return
	}

	example := os.Args[1]
	n := 1
	var err error

	if len(os.Args) <= 4 {
		n, err = strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Printf("Could not convert '%s' to integer, running a single client process\n", os.Args[2])
			n = 1
		}
	}

	runConcurrently := false
	if len(os.Args) == 4 {
		if strings.Compare(os.Args[3], "concurrent") == 0 {
			fmt.Println("Will start clients concurrently")
			runConcurrently = true
		} else {
			fmt.Println("Will start clients sequentially")
		}
	}

	//start := time.Now()
	//runExample(example, 1, n)

	var wg sync.WaitGroup
	wg.Add(n)

	start := time.Now()

	//waitc := make(chan struct{})
	for i := 0; i < n; i++ {
		fmt.Printf("Running client #%d\n", i)
		if runConcurrently {
			go func() {
				defer wg.Done()
				runExample(example, i, n)
			}()
		} else {
			runExample(example, i, n)
		}
	}
	//<-waitc

	wg.Wait()

	elapsed := time.Since(start)
	fmt.Printf("Time: %v seconds", elapsed.Seconds())

	return
}

func runExample(example string, i int, n int) {
	//defer wg.Done()

	switch example {
	case "pedersen", "pedersen-zkp", "pedersen-zkpok":
		examples.GenericClient(i, example, n)
		//examples.Pedersen()
	case "pedersen_ec", "pedersen_ec-zkp", "pedersen_ec-zkpok":
		examples.GenericClient(i, example, n)
		//examples.PedersenEC()
	case "pedersen_ec_stream":
		//examples.PedersenECStream()
		examples.GenericClient(i, example, n)
	case "schnorr", "schnorr-zkp", "schnorr-zkpok":
		//protocolType := getProtocolType(example)
		//examples.Schnorr(protocolType)
		examples.GenericClient(i, example, n)
	case "schnorr_ec", "schnorr_ec-zkp", "schnorr_ec-zkpok":
		//protocolType := getProtocolType(example)
		//examples.SchnorrEC(protocolType)
		examples.GenericClient(i, example, n)
	case "cspaillier", "cspaillier-zkp", "cspaillier-zkpok":
		//dir := config.LoadKeyDirFromConfig()
		//pubKeyPath := filepath.Join(dir, "cspaillierpubkey.txt")
		//examples.Paillier(pubKeyPath)
		examples.GenericClient(i, example, n)
	default:
		fmt.Printf("ERROR: Invalid example: %s\n", example)
	}

	//fmt.Printf("[%d] done\n", i)
}

func getProtocolType(name string) common.ProtocolType {
	if strings.Contains(name, "zkpok") {
		return common.ZKPOK
	} else if strings.Contains(name, "zkp") {
		return common.ZKP
	}
	return common.Sigma
}
