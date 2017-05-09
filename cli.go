package main

import (
	"flag"
	"math/big"
	"fmt"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlogproofs"
	"github.com/xlab-si/emmy/secretsharing"
	"github.com/xlab-si/emmy/encryption"
	"github.com/xlab-si/emmy/pseudonymsys"
	"github.com/pkg/profile" // go tool pprof -text emmy /tmp/profile102918543/cpu.pprof
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
    examplePtr := flag.String("example", "pedersen", "which example to run")
    clientPtr := flag.Bool("client", false, "whether this is a client or server")

    flag.Parse()
    
    if *examplePtr == "pedersen" {
	    if (*clientPtr == true) {	   		
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
			    	
	    } else {
			defer profile.Start().Stop()
			
	    	receiver := commitments.NewPedersenProtocolServer()
	    	receiver.Listen()
	    }
	} else if *examplePtr == "pedersen_ec" {
	    if (*clientPtr == true) {	   		
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
			    	
	    } else {
	    	receiver := commitments.NewPedersenECProtocolServer()
	    	receiver.Listen()
	    }
	} else if strings.Contains(*examplePtr, "schnorr") && !strings.Contains(*examplePtr, "schnorr_ec") {
		var protocolType common.ProtocolType 
   		if *examplePtr == "schnorr" {
   			protocolType = common.Sigma
   		} else if *examplePtr == "schnorr_zkp" {
   			protocolType = common.ZKP
   		} else if *examplePtr == "schnorr_zkpok" {
   			protocolType = common.ZKPOK
   		}
	    if (*clientPtr == true) {
	    	log.Println(protocolType)
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
			    	
	    } else {
	    	log.Println(protocolType)
	    	schnorrServer := dlogproofs.NewSchnorrProtocolServer(protocolType)
	    	schnorrServer.Listen()
	    	
	    }
	} else if strings.Contains(*examplePtr, "schnorr_ec") {
		var protocolType common.ProtocolType 
   		if *examplePtr == "schnorr_ec" {
   			protocolType = common.Sigma
   		} else if *examplePtr == "schnorr_ec_zkp" {
   			protocolType = common.ZKP
   		} else if *examplePtr == "schnorr_ec_zkpok" {
   			protocolType = common.ZKPOK
   		}
	    if (*clientPtr == true) {	
	    	schnorrECProtocolClient, _ := 
	    		dlogproofs.NewSchnorrECProtocolClient(protocolType)
			secret := big.NewInt(345345345334)
	    	proved, _ := schnorrECProtocolClient.Run(secret)	
	    	
	    	if proved {
	    		log.Println("proved")
			} else {
	    		log.Println("NOT proved")
			}
			    	
	    } else {
	    	schnorrZKPECProtocolServer := dlogproofs.NewSchnorrECProtocolServer(protocolType)
	    	schnorrZKPECProtocolServer.Listen()
	    }
	} else if *examplePtr == "split_secret" {
		if (*clientPtr == true) {
			
	    } else {
			dealer, _ := secretsharing.NewDealer()	    	
			secret := "password"
			k := 10
			n := 12
			points, prime, _ := dealer.SplitSecret(secret, k, n)
			
			// take k points and recover secret
			i := 0
			shares := make(map[*big.Int]*big.Int)
			for key, v := range points { 
				if i == k {
					break
				}
				shares[key] = v
				i += 1
			}
					
			recoveredSecret := dealer.RecoverSecret(shares, prime)
			log.Println(recoveredSecret)
	    }
	} else if *examplePtr == "cspaillier" {
		// generate file keys with encryption_test
		dir := config.LoadKeyDirFromConfig()

		if (*clientPtr == true) {
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
			
	    } else {
			secKeyPath := filepath.Join(dir, "cspaillierseckey.txt")
			
	    	cspaillierProtocolServer, err := encryption.NewCSPaillierProtocolServer(secKeyPath)
	    	log.Println(err)
	    	cspaillierProtocolServer.Listen()
	    }
	} else if *examplePtr == "dlog_equality" {
		dlog := config.LoadPseudonymsysDLogFromConfig()
		
		secret := big.NewInt(213412)
		groupOrder := new(big.Int).Sub(dlog.P, big.NewInt(1)) 
		g1, _ := common.GetGeneratorOfZnSubgroup(dlog.P, groupOrder, dlog.OrderOfSubgroup)
		g2, _ := common.GetGeneratorOfZnSubgroup(dlog.P, groupOrder, dlog.OrderOfSubgroup)

		t1, _ := dlog.Exponentiate(g1, secret)
		t2, _ := dlog.Exponentiate(g2, secret)
		proved := dlogproofs.RunDLogEquality(secret, g1, g2, t1, t2)
		log.Println(proved)

	} else if *examplePtr == "dlog_equality_blinded_transcript" {
		// no wrappers at the moment, because messages handling will be refactored
		eProver, _ := dlogproofs.NewDLogEqualityBTranscriptProver()
		eVerifier, _ := dlogproofs.NewDLogEqualityBTranscriptVerifier()

		secret := big.NewInt(213412)
		groupOrder := new(big.Int).Sub(eProver.DLog.P, big.NewInt(1)) 
		g1, _ := common.GetGeneratorOfZnSubgroup(eProver.DLog.P, groupOrder, eProver.DLog.OrderOfSubgroup)
		g2, _ := common.GetGeneratorOfZnSubgroup(eProver.DLog.P, groupOrder, eProver.DLog.OrderOfSubgroup)
		
		t1, _ := eProver.DLog.Exponentiate(g1, secret)
	    t2, _ := eProver.DLog.Exponentiate(g2, secret)
	    
		x1, x2 := eProver.GetProofRandomData(secret, g1, g2)

		challenge := eVerifier.GetChallenge(g1, g2, t1, t2, x1, x2)
		z := eProver.GetProofData(challenge)
		verified, transcript, G2, T2 := eVerifier.Verify(z)

		log.Println(verified)
		
		log.Println("is the transcript valid:")
		valid := dlogproofs.VerifyBlindedTranscript(transcript, eProver.DLog, g1, t1, G2, T2)
		log.Println(valid)
	} else if *examplePtr == "nymgen" {
		orgName := "todo"
		orgAddress := "todo"
		user := pseudonymsys.NewUser(orgName, orgAddress)
		org := pseudonymsys.NewOrganization()
		
		a_tilde, b_tilde := user.GetFirstPseudonymGenMsg()
		a := org.GetFirstPseudonymsysGenReply(a_tilde, b_tilde)
		
		x1, x2 := user.GetPseudonymGenRandomProofData(a)
		challenge := org.GetPseudonymGenChallenge(x1, x2)

		z := user.GetPseudonymGenProofData(challenge)
		verified := org.PseudonymGenVerify(z)
	
		log.Println(verified)
		if verified {
			nymA, nymB := user.GetNym()	
			log.Println(nymA)
			log.Println(nymB)
			// todo: store in some DB: (orgName, nymA, nymB)
		}
	}
	
    //fmt.Println("word:", *wordPtr)
    //fmt.Println("numb:", *numbPtr)
    //fmt.Println("tail:", flag.Args()) // any arguments at the end
}

