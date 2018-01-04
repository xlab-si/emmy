/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package groups

import (
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
)

// Zn presents Z_n* - group of all integers smaller than n and coprime with n.
// Note that this group is NOT cyclic (as opposed for example to Schnorr group).
// It is cyclic when n is prime, but the problem with Z_p* is that the generator
// is difficult to find (as opposed to Schnorr group and QRSpecialRSA).
type Zn struct {
	N *big.Int
}

func NewZn(n *big.Int) *Zn {
	return &Zn{
		N: n,
	}
}

// GetRandomElement returns a random element from this group. Elements of this group
// are integers that are coprime with N.
func (group *Zn) GetRandomElement() *big.Int {
	return common.GetRandomZnInvertibleElement(group.N)
}

// Mul computes x * y mod group.N.
func (group *Zn) Mul(x, y *big.Int) *big.Int {
	r := new(big.Int)
	r.Mul(x, y)
	r.Mod(r, group.N)
	return r
}

// Exp computes x^exponent mod group.N.
func (group *Zn) Exp(x, exponent *big.Int) *big.Int {
	r := new(big.Int)
	r.Exp(x, exponent, group.N)
	return r
}

// Inv computes inverse of x, that means xInv such that x * xInv = 1 mod group.N.
func (group *Zn) Inv(x *big.Int) *big.Int {
	return new(big.Int).ModInverse(x, group.N)
}

// IsElementInGroup returns true if x is in the group and false otherwise. An element x is
// in Zn when it is coprime with group.N, that means gcd(x, group.N) = 1.
func (group *Zn) IsElementInGroup(x *big.Int) bool {
	c := new(big.Int).GCD(nil, nil, x, group.N)
	return x.Cmp(group.N) < 0 && c.Cmp(big.NewInt(1)) == 0
}
