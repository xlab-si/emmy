package tests

import (
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/encryption"
	"github.com/xlab-si/emmy/common"
	"github.com/mancabizjak/emmy/config"
	"math/big"
	"path/filepath"
	"testing"
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
	secParams := encryption.CSPaillierSecParams {
		L: 512,
		RoLength: 160,
		K: 158,
		K1: 158,
	}

	dir := config.LoadTestKeyDirFromConfig()
	secKeyPath := filepath.Join(dir, "cspaillierseckey.txt")
	pubKeyPath := filepath.Join(dir, "cspaillierpubkey.txt")

	cspaillier := encryption.NewCSPaillier(&secParams)
	cspaillier.StoreSecKey(secKeyPath)
	cspaillier.StorePubKey(pubKeyPath)
	
	cspaillierPub, _ := encryption.NewCSPaillierFromPubKeyFile(pubKeyPath)
	
	m := common.GetRandomInt(big.NewInt(8685849))
	label := common.GetRandomInt(big.NewInt(340002223232))
	u, e, v, _ := cspaillierPub.Encrypt(m, label)
	
	cspaillierSec, _ := encryption.NewCSPaillierFromSecKey(secKeyPath)
	p, _ := cspaillierSec.Decrypt(u, e, v, label)
	
	assert.Equal(t, m, p, "Camenisch-Shoup modified Paillier encryption/decryption does not work correctly")
}




