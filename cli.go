package main

import (
	"flag"
	//"github.com/pkg/profile" // go tool pprof -text emmy /tmp/profile102918543/cpu.pprof
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlogproofs"
	"github.com/xlab-si/emmy/secretsharing"
	"log"
	"math/big"
)

// Run server (verifier) in one terminal, for example for SchnorrEC:
// emmy -example=schnorr_ec -client=false
// Run client (prover) in another:
// emmy -example=schnorr_ec -client=true

// Verifiable encryption
// emmy -example=cspaillier -client=false
// emmy -example=cspaillier -client=true

func oldCli() {
	examplePtr := flag.String("example", "pedersen", "which example to run")
	clientPtr := flag.Bool("client", false, "whether this is a client or server")

	flag.Parse()

	if *examplePtr == "split_secret" {
		if *clientPtr == true {

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
	} else if *examplePtr == "dlog_equality" {
		dlog := config.LoadDLog("pseudonymsys")

		secret := big.NewInt(213412)
		groupOrder := new(big.Int).Sub(dlog.P, big.NewInt(1))
		g1, _ := common.GetGeneratorOfZnSubgroup(dlog.P, groupOrder, dlog.OrderOfSubgroup)
		g2, _ := common.GetGeneratorOfZnSubgroup(dlog.P, groupOrder, dlog.OrderOfSubgroup)

		t1, _ := dlog.Exponentiate(g1, secret)
		t2, _ := dlog.Exponentiate(g2, secret)
		proved := dlogproofs.RunDLogEquality(secret, g1, g2, t1, t2, dlog)
		log.Println(proved)

	} else if *examplePtr == "dlog_equality_blinded_transcript" {
		dlog := config.LoadDLog("pseudonymsys")

		// no wrappers at the moment, because messages handling will be refactored
		eProver := dlogproofs.NewDLogEqualityBTranscriptProver(dlog)
		eVerifier := dlogproofs.NewDLogEqualityBTranscriptVerifier(dlog, nil)

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
	}

	//fmt.Println("word:", *wordPtr)
	//fmt.Println("numb:", *numbPtr)
	//fmt.Println("tail:", flag.Args()) // any arguments at the end
}
