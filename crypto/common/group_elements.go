package common

import (
	"math/big"
)

// GetZnInvertibleElement returns element from Z_n*.
func GetZnInvertibleElement(n *big.Int) *big.Int {
	var r *big.Int
	for {
		r = GetRandomInt(n)
		if new(big.Int).GCD(nil, nil, r, n).Cmp(big.NewInt(1)) == 0 {
			break
		}
	}
	return r
}
