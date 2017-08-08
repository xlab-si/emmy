package test

import (
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	//"github.com/xlab-si/emmy/dlogproofs"
	"github.com/xlab-si/emmy/pseudonymsys"
	"testing"
)

func TestPseudonymsysEC(t *testing.T) {
	dlog := dlog.NewECDLog(dlog.P256)
	caClient, err := client.NewPseudonymsysCAClientEC(testGrpcServerEndpoint)
	if err != nil {
		t.Errorf("Error when initializing NewPseudonymsysCAClientEC")
	}

	userSecret := config.LoadPseudonymsysUserSecret("user1", "ecdlog")

	nymA := common.NewECGroupElement(dlog.Curve.Params().Gx, dlog.Curve.Params().Gy)
	nymB1, nymB2 := dlog.Exponentiate(nymA.X, nymA.Y, userSecret) // this is user's public key
	nymB := common.NewECGroupElement(nymB1, nymB2)

	masterNym := pseudonymsys.NewPseudonymEC(nymA, nymB)
	caCertificate, err := caClient.ObtainCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA")
	}

	// usually the endpoint is different from the one used for CA:
	c1, err := client.NewPseudonymsysClientEC(testGrpcServerEndpoint)
	nym1, err := c1.GenerateNym(userSecret, caCertificate)
	if err != nil {
		t.Errorf(err.Error())
	}

	orgName := "org1"
	h1X, h1Y, h2X, h2Y := config.LoadPseudonymsysOrgPubKeysEC(orgName)
	h1 := common.NewECGroupElement(h1X, h1Y)
	h2 := common.NewECGroupElement(h2X, h2Y)
	orgPubKeys := pseudonymsys.NewOrgPubKeysEC(h1, h2)
	credential, err := c1.ObtainCredential(userSecret, nym1, orgPubKeys)
	if err != nil {
		t.Errorf(err.Error())
	}

	// register with org2
	// create a client to communicate with org2
	caClient1, err := client.NewPseudonymsysCAClientEC(testGrpcServerEndpoint)
	caCertificate1, err := caClient1.ObtainCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA")
	}

	c2, err := client.NewPseudonymsysClientEC(testGrpcServerEndpoint)
	nym2, err := c2.GenerateNym(userSecret, caCertificate1)
	if err != nil {
		t.Errorf(err.Error())
	}

	authenticated, err := c2.TransferCredential(orgName, userSecret, nym2, credential)
	if err != nil {
		t.Errorf(err.Error())
	}

	assert.Equal(t, authenticated, true, "Pseudonymsys test failed")
}
