package tests

import (
	"testing"
	"math/big"
	"github.com/stretchr/testify/assert"	
	"github.com/xlab-si/emmy/encryption"
	"github.com/xlab-si/emmy/common"
)

func TestPaillier(t *testing.T) {
	paillier := encryption.NewPaillier(1024)	
	pubKey := paillier.GetPubKey()
	
	m := common.GetRandomInt(big.NewInt(123412341234123))
	pubPaillier := encryption.NewPubPaillier(pubKey)
	c, _ := pubPaillier.Encrypt(m)
	p, _ := paillier.Decrypt(c)
	
	assert.Equal(t, m, p, "Paillier encryption/decryption does not work correctly")
}

func TestCSPaillier(t *testing.T) {
	secParams := encryption.CSPaillierSecParams{
		L: 512,
		RoLength: 160,
		K: 158,
		K1: 158,
	}	
	cspaillier := encryption.NewCSPaillier(&secParams)
	secPath := "/home/mihas/work/src/github.com/xlab-si/emmy/demokeys/cspaillierseckey.txt"
	cspaillier.StoreSecKey(secPath)
	pubPath := "/home/mihas/work/src/github.com/xlab-si/emmy/demokeys/cspaillierpubkey.txt"
	cspaillier.StorePubKey(pubPath)
	
	cspaillierPub, _ := encryption.NewCSPaillierFromPubKeyFile(pubPath)
	
	m := common.GetRandomInt(big.NewInt(8685849))
	label := common.GetRandomInt(big.NewInt(340002223232))
	u, e, v, _ := cspaillierPub.Encrypt(m, label)
	
	secKeyPath := "/home/mihas/work/src/github.com/xlab-si/emmy/demokeys/cspaillierseckey.txt"
	cspaillierSec, _ := encryption.NewCSPaillierFromSecKey(secKeyPath)
	p, _ := cspaillierSec.Decrypt(u, e, v, label)
	
	assert.Equal(t, m, p, "Camenisch-Shoup modified Paillier encryption/decryption does not work correctly")
}




