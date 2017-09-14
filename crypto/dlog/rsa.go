package dlog

import (
	"math/big"
	"crypto/rand"
	"crypto/rsa"
)

// TODO: dlog will be renamed into cproblems (as computational problems)

type RSA struct {
	N       *big.Int // N = P * Q
	P1 		*big.Int
	P2		*big.Int
}

func NewRSA(nBitLength int) (*RSA, error) {
	priv, err := rsa.GenerateKey(rand.Reader, nBitLength)
	if err != nil {
		return nil, err
	}
	p1 := priv.Primes[0]
	p2 := priv.Primes[1]
	n := new(big.Int).Mul(p1, p2)
	return &RSA {
		P1: p1,
		P2: p2,
		N: n,
	}, nil
}


