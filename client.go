package main

import (
	"fmt"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/examples"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		fmt.Printf("Running client #%d\n", i)
		if runConcurrently {
			go runExample(example, i, &wg)
		} else {
			runExample(example, i, &wg)
		}
	}
	wg.Wait()
	return
}

func runExample(example string, i int, wg *sync.WaitGroup) {
	defer wg.Done()

	switch example {
	case "pedersen":
		examples.Pedersen()
		break
	case "pedersen_ec":
		examples.PedersenEC()
		break
	case "schnorr", "schnorr_zkp", "schnorr_zkpok":
		protocolType := getProtocolType(example)
		examples.Schnorr(protocolType)
		break
	case "schnorr_ec", "schnorr_ec_zkp", "schnorr_ec_zkpok":
		protocolType := getProtocolType(example)
		examples.SchnorrEC(protocolType)

	case "cspaillier":
		dir := config.LoadKeyDirFromConfig()
		pubKeyPath := filepath.Join(dir, "cspaillierpubkey.txt")
		examples.Paillier(pubKeyPath)
		break

	default:
		fmt.Printf("ERROR: Invalid example: %s\n", example)
	}

	fmt.Printf("[%d] done\n", i)
}

func getProtocolType(name string) common.ProtocolType {
	if strings.Contains(name, "zkpok") {
		return common.ZKPOK
	} else if strings.Contains(name, "zkp") {
		return common.ZKP
	}
	return common.Sigma
}
