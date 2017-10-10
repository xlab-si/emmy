package common

import (
	"crypto/rand"
	"errors"
	"log"
	"math/big"
)

// Returns random integer from [0, max).
func GetRandomInt(max *big.Int) *big.Int {
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Fatal(err)
	}
	return n
}

// Returns random integer from [min, max).
func GetRandomIntFromRange(min, max *big.Int) (*big.Int, error) {
	if min.Cmp(max) >= 0 {
		err := errors.New("GetRandomIntFromRange: max has to be bigger than min")
		return nil, err
	}
	if min.Cmp(big.NewInt(0)) < 0 && max.Cmp(big.NewInt(0)) < 0 {
		d := new(big.Int).Sub(min, max)
		dAbs := new(big.Int).Abs(d)
		i := GetRandomInt(dAbs)
		ic := new(big.Int).Add(min, i)
		return ic, nil
	} else if min.Cmp(big.NewInt(0)) < 0 && max.Cmp(big.NewInt(0)) >= 0 {
		nMin := new(big.Int).Abs(min)
		d := new(big.Int).Add(nMin, max)
		i := GetRandomInt(d)
		ic := new(big.Int).Add(min, i)
		return ic, nil
	} else {
		d := new(big.Int).Sub(max, min)
		i := GetRandomInt(d)
		ic := new(big.Int).Add(min, i)
		return ic, nil
	}
}

// GetRandomIntOfLength returns random *big.Int exactly of length bitLengh.
func GetRandomIntOfLength(bitLength int) *big.Int {
	// choose a random number a of length bitLength
	// that means: 2^(bitLength-1) < a < 2^(bitLength)
	// choose a random from [0, 2^(bitLength-1)) and add it to 2^(bitLength-1)
	max := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitLength-1)), nil)
	o := GetRandomInt(max)
	r := new(big.Int).Add(max, o)

	b1 := r.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitLength-1)), nil))
	b2 := r.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitLength)), nil))
	if (b1 != 1) || (b2 != -1) {
		log.Panic("parameter not properly chosen")
	}

	return r
}

// GetZnInvertibleElement returns random element from Z_n*.
func GetRandomZnInvertibleElement(n *big.Int) *big.Int {
	for {
		r := GetRandomInt(n)
		if new(big.Int).GCD(nil, nil, r, n).Cmp(big.NewInt(1)) == 0 {
			return r
		}
	}
}
