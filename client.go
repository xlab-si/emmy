package main

import (
	"flag"
	"math/big"
	"fmt"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlogproofs"
	//"github.com/xlab-si/emmy/secretsharing"
	"github.com/xlab-si/emmy/encryption"
	"path/filepath"
	"strings"
	"log"
)

// Run server (verifier) in one terminal, for example for SchnorrEC:
// emmy -example=schnorr_ec -client=false
// Run client (prover) in another:
// emmy -example=schnorr_ec -client=true

// Verifiable encryption
// emmy -example=cspaillier -client=false
// emmy -example=cspaillier -client=true

func main() {
    example := flag.String("example", "pedersen", "which example to run")
    flag.Parse()
    
    switch *example {
    	case "pedersen":
    		pedersenProtocolClient := commitments.NewPedersenProtocolClient()
	    	
			err := pedersenProtocolClient.ObtainH()
			if err != nil {
				fmt.Println("getting h not successful")
				fmt.Println(err)
			}
	    	
			valToBeCommitted := big.NewInt(121212121)
			success, err := pedersenProtocolClient.Commit(valToBeCommitted) // TODO: this should return only err
			if err != nil {
				fmt.Println("commit not successful")
				fmt.Println(err)
			}
			if success == true {
				//fmt.Println("ok")
			}
		    	
			success, err = pedersenProtocolClient.Decommit()
			if err != nil {
				fmt.Println("commit not successful")
				fmt.Println(err)
			}
			if success == true {
				fmt.Println("ok")
			} else {
				fmt.Println("not ok")
			}
			break
		case "pedersen_ec":
			pedersenProtocolClient := commitments.NewPedersenECProtocolClient()
	    	
			err := pedersenProtocolClient.ObtainH()
			if err != nil {
				fmt.Println("getting h not successful")
				fmt.Println(err)
			}
	    	
			valToBeCommitted := big.NewInt(121212121)
			success, err := pedersenProtocolClient.Commit(valToBeCommitted) // TODO: this should return only err
			if err != nil {
				fmt.Println("commit not successful")
				fmt.Println(err)
			}
			if success == true {
				//fmt.Println("ok")
			}
		    	
			success, err = pedersenProtocolClient.Decommit()
			if err != nil {
				fmt.Println("commit not successful")
				fmt.Println(err)
			}
			if success == true {
				fmt.Println("ok")
			} else {
				fmt.Println("not ok")
			}
			break

		case "schnorr", "schnorr_zkp", "schnorr_zkpok":
			protocolType := getProtocolType(*example)
			schnorrProtocolClient, err := dlogproofs.NewSchnorrProtocolClient(protocolType)
			if err != nil {
				log.Fatalf("error when creating Schnorr protocol client: %v", err)
			}
			
			secret := big.NewInt(345345345334)
			isProved, err := schnorrProtocolClient.Run(secret)
			
			if isProved == true {
				log.Println("knowledge proved")
			} else {
				log.Println("knowledge NOT proved")
			}
			break
		
		case "schnorr_ec",  "schnorr_ec_zkp", "schnorr_ec_zkpok":
			protocolType := getProtocolType(*example)
			schnorrECProtocolClient, _ := dlogproofs.NewSchnorrECProtocolClient(protocolType)
			secret := big.NewInt(345345345334)
	    	proved, _ := schnorrECProtocolClient.Run(secret)	
	    	
	    	if proved {
	    		log.Println("proved")
			} else {
	    		log.Println("NOT proved")
			}
			break
		
		case "cspaillier":
			dir := config.LoadKeyDirFromConfig()

			pubKeyPath := filepath.Join(dir, "cspaillierpubkey.txt")
	    	cspaillierProtocolClient, _ := encryption.NewCSPaillierProtocolClient(pubKeyPath)
	    	
			m := common.GetRandomInt(big.NewInt(8685849))
			label := common.GetRandomInt(big.NewInt(340002223232))
			
	    	proved, _ := cspaillierProtocolClient.Run(m, label)
	    	if proved {
	    		log.Println("proved")
			} else {
	    		log.Println("NOT proved")
			}
			break

		default:
			fmt.Printf("ERROR: Invalid example: %s", *example)
    }

}

func getProtocolType(name string) common.ProtocolType {
	if strings.Contains(name, "zkpok") {
		return common.ZKPOK
	} else if strings.Contains(name, "zkp") {
		return common.ZKP
	}
	return common.Sigma
}
