package examples

import (
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlogproofs"
	"log"
	"math/big"
)

func Schnorr(protocolType common.ProtocolType) {

	schnorrProtocolClient, err := dlogproofs.NewSchnorrProtocolClient(protocolType)
	if err != nil {
		log.Fatalf("Error when creating Schnorr protocol client: %v", err)
	}

	secret := big.NewInt(345345345334)
	isProved, err := schnorrProtocolClient.Run(secret)

	if isProved == true {
		log.Println("Knowledge proved")
	} else {
		log.Println("Knowledge NOT proved")
	}
}