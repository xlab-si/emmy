package zn

import (
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
)

// GroupZp represents is a special case of the Z_n* group, where n is a prime.
// The group is cyclic, however the generator of the group is difficult to find
// (as opposed to Schnorr group and qr.RSASpecial group).
type GroupZp struct {
	*Group
	Order *big.Int
}

func NewGroupZp(p *big.Int) (*GroupZp, error) {
	if !p.ProbablyPrime(20) {
		return nil, fmt.Errorf("p is not a prime")
	}

	return &GroupZp{
		Group: NewGroup(p),
		Order: new(big.Int).Sub(p, big.NewInt(1)),
	}, nil
}

// GetGeneratorOfSubgroup returns a generator of a subgroup of a specified order in Z_n.
// Parameter groupOrder is order of Z_n (if n is prime, order is n-1).
func (zp *GroupZp) GetGeneratorOfSubgroup(subgroupOrder *big.Int) (*big.Int, error) {
	if big.NewInt(0).Mod(zp.Order, subgroupOrder).Cmp(big.NewInt(0)) != 0 {
		err := fmt.Errorf("subgroupOrder does not divide groupOrder")
		return nil, err
	}
	r := new(big.Int).Div(zp.Order, subgroupOrder)
	for {
		h := common.GetRandomInt(zp.N)
		g := new(big.Int)
		g.Exp(h, r, zp.N)
		if g.Cmp(big.NewInt(1)) != 0 {
			return g, nil
		}
	}
}
