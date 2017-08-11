package common

import (
	"crypto/dsa"
	"crypto/rand"
	"errors"
	"log"
	"math/big"
)

// It returns primes p and q where p = r * q + 1 for some integer r.
func GetSchnorrGroup(qBitLength int) (*big.Int, *big.Int, *big.Int, error) {
	// Using DSA GenerateParameters:

	sizes := dsa.L1024N160

	if qBitLength == 160 {
		sizes = dsa.L1024N160
	} else if qBitLength == 224 {
		sizes = dsa.L2048N224
	} else if qBitLength == 256 {
		sizes = dsa.L2048N256
		//} else if qBitLength == 256 {
		//	sizes = dsa.L3072N256
	} else {
		err := errors.New("generating Schnorr primes for these bitlengths is not supported")
		return nil, nil, nil, err
	}

	params := dsa.Parameters{}
	err := dsa.GenerateParameters(&params, rand.Reader, sizes)
	log.Println(err)
	if err == nil {
		return params.G, params.Q, params.P, nil
	} else {
		return nil, nil, nil, err
	}
}
