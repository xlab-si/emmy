package examples

import (
	"github.com/xlab-si/emmy/commitments"
	"log"
	"math/big"
)

func PedersenEC() {

	client := commitments.NewPedersenECProtocolClient()

	commitVal := big.NewInt(121212121)
	success, err := client.Run(commitVal)

	if err != nil {
		log.Printf("Error: %v", err)
	}

	if success == true {
		log.Println("ok")
	} else {
		log.Println("not ok")
	}

}
