package tests

import (
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/signatures"
	"log"
	"math/big"
	"testing"
)

func TestCL(t *testing.T) {
	numOfBlocks := 2
	cl := signatures.NewCL(numOfBlocks)
	n := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(160)), nil)
	//n, _ := new(big.Int).SetString("26959946667150639794667015087019630673557916260026308143510066298881", 10)

	m1 := common.GetRandomInt(n)
	m2 := common.GetRandomInt(n)
	var m_Ls []*big.Int
	m_Ls = append(m_Ls, m1)
	m_Ls = append(m_Ls, m2)

	signature, err := cl.Sign(m_Ls)
	if err != nil {
		log.Println(err)
	}

	pubKey := cl.GetPubKey()
	pubCL := signatures.NewPubCL(pubKey)
	ok, _ := pubCL.Verify(m_Ls, signature)
	log.Println(ok)
}
