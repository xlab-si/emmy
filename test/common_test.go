package tests

import (
	"testing"
	"github.com/stretchr/testify/assert"	
	"math/big"
	"github.com/xlab-si/emmy/common"
	"log"
)

func TestLCM(t *testing.T) {
	a := big.NewInt(8)
	b := big.NewInt(6)
	lcm := common.LCM(a, b)
	assert.Equal(t, lcm, big.NewInt(24), "LCM returned wrong value")
}

func TestGetGermainPrime(t *testing.T) {
	p := common.GetGermainPrime(512)
	p1 := new(big.Int).Add(p, p)
	p1.Add(p1, big.NewInt(1))
	
	assert.Equal(t, p.ProbablyPrime(20), true, "p should be prime")
	assert.Equal(t, p1.ProbablyPrime(20), true, "p1 should be prime")
}

func TestGetSafePrime(t *testing.T) {
	p, err := common.GetSafePrime(512)
	if err != nil {
		log.Println(err)
	}
	p1 := new(big.Int)
	p1.Sub(p, big.NewInt(1))
	p1.Div(p1, big.NewInt(2))
	
	assert.Equal(t, p.ProbablyPrime(20), true, "p should be prime")
	assert.Equal(t, p1.ProbablyPrime(20), true, "p1 should be prime")
}

func TestGeneratorOfCompositeQR(t *testing.T) {
	p, _ := common.GetSafePrime(512)
	q, _ := common.GetSafePrime(512)
	g, _ := common.GetGeneratorOfCompositeQR(p, q)
	n := new(big.Int).Mul(p, q)
	    	
	p1 := new(big.Int)
	p1.Sub(p, big.NewInt(1))
	p1.Div(p1, big.NewInt(2))
	q1 := new(big.Int)
	q1.Sub(q, big.NewInt(1))
	q1.Div(q1, big.NewInt(2))
	
	// order of g should be 2*p1*q1
	order := new(big.Int).Mul(p1, q1)
	order.Mul(order, big.NewInt(2))
	tmp := new(big.Int).Exp(g, order, n)
	
	assert.Equal(t, tmp, big.NewInt(1), "g is not a generator")
	// other possible orders in this group are: 2, p1, q1, 2 * p1, and 2 * q1.
	tmp = new(big.Int).Exp(g, big.NewInt(2), n)
	assert.NotEqual(t, tmp, big.NewInt(1), "g is not a generator")
	
	tmp = new(big.Int).Exp(g, p1, n)
	assert.NotEqual(t, tmp, big.NewInt(1), "g is not a generator")
	
	tmp = new(big.Int).Exp(g, q1, n)
	assert.NotEqual(t, tmp, big.NewInt(1), "g is not a generator")
	
	tmp = new(big.Int).Exp(g, q1.Mul(p1, big.NewInt(2)), n)
	assert.NotEqual(t, tmp, big.NewInt(1), "g is not a generator")
	
	tmp = new(big.Int).Exp(g, q1.Mul(q1, big.NewInt(2)), n)
	assert.NotEqual(t, tmp, big.NewInt(1), "g is not a generator")
}

func TestGetGeneratorOfZnSubgroup(t *testing.T) {
	p, err := common.GetSafePrime(512)
	if err != nil {
		log.Println(err)
	}
	pMin := new(big.Int)
	pMin.Sub(p, big.NewInt(1))
	p1 := new(big.Int).Div(pMin, big.NewInt(2))

	g, err := common.GetGeneratorOfZnSubgroup(p, pMin, p1)
	if err != nil {
		log.Println(err)
	}
	g.Exp(g, big.NewInt(0).Sub(p1, big.NewInt(1)), p1) // g^(p1-1) % p1 should be 1
	
	assert.Equal(t, g, big.NewInt(1), "not a generator")
}



