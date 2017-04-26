package examples

import (
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlogproofs"
	"log"
	"math/big"
)

func SchnorrEC(protocolType common.ProtocolType) {

	schnorrECProtocolClient, _ := dlogproofs.NewSchnorrECProtocolClient(protocolType)
	secret := big.NewInt(345345345334)
	proved, _ := schnorrECProtocolClient.Run(secret)	
	
	if proved {
		log.Println("Knowledge proved")
	} else {
		log.Println("Knowlegde NOT proved")
	}
}