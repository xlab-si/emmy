package dlog

import (
	"math/big"
)

type DLog interface {
	Multiply(...*big.Int) (*big.Int, *big.Int)
	Exponentiate(...*big.Int) (*big.Int, *big.Int)
	ExponentiateBaseG(*big.Int) (*big.Int, *big.Int)
	GetOrderOfSubgroup() *big.Int
}
