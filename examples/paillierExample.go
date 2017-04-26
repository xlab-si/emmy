package examples

import (
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/encryption"
	"log"
	"math/big"
)

func Paillier(pubKeyPath string) {

	cspaillierProtocolClient, _ := encryption.NewCSPaillierProtocolClient(pubKeyPath)

	m := common.GetRandomInt(big.NewInt(8685849))
	label := common.GetRandomInt(big.NewInt(340002223232))

	proved, _ := cspaillierProtocolClient.Run(m, label)
	if proved {
		log.Println("proved")
	} else {
		log.Println("NOT proved")
	}
}
