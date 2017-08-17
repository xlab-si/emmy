package common

import (
	"errors"
	"math/big"
)

// GetGeneratorOfZnSubgroup returns a generator of a subgroup of a specified order in Z_n.
// Parameter groupOrder is order of Z_n (if n is prime, order is n-1).
func GetGeneratorOfZnSubgroup(n, groupOrder, subgroupOrder *big.Int) (*big.Int, error) {
	if big.NewInt(0).Mod(groupOrder, subgroupOrder).Cmp(big.NewInt(0)) != 0 {
		err := errors.New("subgroupOrder does not divide groupOrder")
		return nil, err
	}
	r := new(big.Int).Div(groupOrder, subgroupOrder)
	for {
		h := GetRandomInt(n)
		g := new(big.Int)
		g.Exp(h, r, n)
		if g.Cmp(big.NewInt(1)) != 0 {
			return g, nil
		}
	}
}

// GetGeneratorOfCompositeQR returns a generator of a group of quadratic residues.
// The parameters p and q need to be safe primes.
func GetGeneratorOfCompositeQR(p, q *big.Int) (g *big.Int, err error) {
	n := new(big.Int).Mul(p, q)
	one := big.NewInt(1)
	two := big.NewInt(2)
	tmp := new(big.Int)

	// check if p and q are safe primes:
	p1 := new(big.Int)
	p1.Sub(p, one)
	p1.Div(p1, two)
	q1 := new(big.Int)
	q1.Sub(q, one)
	q1.Div(q1, two)

	if p.ProbablyPrime(20) && q.ProbablyPrime(20) && p1.ProbablyPrime(20) && q1.ProbablyPrime(20) {
	} else {
		err := errors.New("p and q need to be safe primes")
		return nil, err
	}

	// The possible orders are 2, p1, q1, 2 * p1, 2 * q1, and 2 * p1 * q1.
	// We need to make sure that all elements of orders smaller than 2 * p1 * q1 are ruled out.

	for {
		a := GetRandomInt(n)
		a_plus := new(big.Int).Add(a, one)
		a_min := new(big.Int).Sub(a, one)
		tmp.GCD(nil, nil, a, p)
		// p
		if tmp.Cmp(one) != 0 {
			continue
		}
		tmp.GCD(nil, nil, a_plus, p)
		if tmp.Cmp(one) != 0 {
			continue
		}
		tmp.GCD(nil, nil, a_min, p)
		if tmp.Cmp(one) != 0 {
			continue
		}

		// q
		tmp.GCD(nil, nil, a, q)
		if tmp.Cmp(one) != 0 {
			continue
		}
		tmp.GCD(nil, nil, a_plus, q)
		if tmp.Cmp(one) != 0 {
			continue
		}
		tmp.GCD(nil, nil, a_min, q)
		if tmp.Cmp(one) != 0 {
			continue
		}

		g := a.Mul(a, big.NewInt(2))
		return g, nil
	}
}
