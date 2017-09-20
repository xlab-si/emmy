package dlog

import (
	"math/big"
	"crypto/rand"
	"crypto/rsa"
)

// TODO: dlog will be renamed into cproblems (as computational problems). EDIT: now that I
// am adding Group interface (currently in common/groups.go), we might simply name this package as groups.

type RSA struct {
	N       *big.Int // N = P1 * P2
	P1 		*big.Int
	P2		*big.Int
	E		*big.Int
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

func NewPublicRSA(n, e *big.Int) *RSA {
	return &RSA {
		N: n,
		E: e,
	}
}

// Exp returns x^E mod N (it is not called Encrypt, because there is no padding).
func (rsa *RSA) Exp(x *big.Int) *big.Int {
	return new(big.Int).Exp(x, rsa.E, rsa.N)
}

