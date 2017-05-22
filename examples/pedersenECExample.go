package examples

import (
	"github.com/xlab-si/emmy/base"
	"github.com/xlab-si/emmy/commitments"
	"log"
	"math/big"
	"strings"
	//"sync"
)

// do checking of clientType before here
func GenericClient(id int, schema string, n int) {
	log.Printf("GenericClient got Id=%d", id)
	schemaTypeVariant := strings.Split(strings.ToUpper(schema), "-")
	log.Println("schemaTypeVariant", schemaTypeVariant, ", len", len(schemaTypeVariant))

	// Spawn the client that will execute the protocol of choice
	clientParams := &base.ClientParams{}
	clientParams.SchemaType = schemaTypeVariant[0]
	if len(schemaTypeVariant) > 1 {
		clientParams.SchemaVariant = schemaTypeVariant[1]
	}
	clientParams.Id = id
	client := base.NewProtocolClient(clientParams)
	log.Printf("Instantiated [Generic client %v]", &client)

	/* ***********************************************************************************
	//TODO Try to actually just call the same client stub from several goroutines here....
	//	... dont just create new clients
	************************************************************************************* */

	// Set the actual values that are to be used to bootstrap the protocol
	protocolParams := base.ProtocolParams{}
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

func PedersenECStream() {
	client := commitments.NewPedersenECStreamProtocolClient()
	commitVal := big.NewInt(121212121)
	client.DoCommitment(commitVal)
}

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
