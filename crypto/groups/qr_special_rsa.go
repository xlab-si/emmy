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

// TODO: move qr.go into groups package, make QR parent of QRSpecialRSA
// TODO: check group_generators.go and move the content into groups

import (
	"github.com/xlab-si/emmy/crypto/common"
	"math/big"
)

// QRSpecialRSA presents group of quadratic residues modulo N where N is a product
// of two safe primes.
type QRSpecialRSA struct {
	N      *big.Int // N = P * Q, P = 2*p + 1, Q = 2*q + 1
	P      *big.Int
	Q      *big.Int
	SmallP *big.Int
	SmallQ *big.Int
	Order  *big.Int // order of group QR_N (it is SmallP * SmallQ)
}

func NewQRSpecialRSA(safePrimeBitLength int) (*QRSpecialRSA, error) {
	specialRSAPrimes, err := common.GetSpecialRSAPrimes(safePrimeBitLength)
	if err != nil {
		return nil, err
	}
	return &QRSpecialRSA{
		N:      new(big.Int).Mul(specialRSAPrimes.P, specialRSAPrimes.Q),
		P:      specialRSAPrimes.P,
		Q:      specialRSAPrimes.Q,
		SmallP: specialRSAPrimes.P1,
		SmallQ: specialRSAPrimes.Q1,
		Order:  new(big.Int).Mul(specialRSAPrimes.P1, specialRSAPrimes.Q1),
	}, nil
}

func NewQRSpecialRSAPublic(N *big.Int) *QRSpecialRSA {
	return &QRSpecialRSA{
		N: N,
	}
}

// GetRandomGenerator returns a generator of a group of quadratic residues QR_N.
func (group *QRSpecialRSA) GetRandomGenerator() *big.Int {
	// The order of QR_n is p1 * q1 (we know Z_n* = Z_p* x Z_q*, it can be shown
	// that QR_n = QR_p x QR_q, the order of QR_p is (p-1)/2 = p1,
	// the order of QR_q is (q-1)/2 = q1).
	// Thus the possible orders of elements in QR_n are: p1, q1, p1 * q1.
	// We need find element of order p1 * q1 (we rule out elements of order p1 and q1).

	for {
		a := common.GetRandomZnInvertibleElement(group.N)
		a.Exp(a, big.NewInt(2), group.N) // make it quadratic residue

		// check if the order is p1
		check1 := group.Exp(a, group.SmallP)
		if check1.Cmp(big.NewInt(1)) == 0 {
			continue
		}

		// check if the order is q1
		check2 := group.Exp(a, group.SmallQ)
		if check2.Cmp(big.NewInt(1)) == 0 {
			continue
		}

		return a
	}
}

// GetRandomElement returns a random element from this group. First a random generator
// is chosen and then it is exponentiated to the random int between 0 and order
// of QR_N (SmallP * SmallQ).
func (group *QRSpecialRSA) GetRandomElement() (*big.Int, error) {
	g := group.GetRandomGenerator()
	r := common.GetRandomInt(group.Order)
	el := group.Exp(g, r)
	return el, nil
}

// Mul computes x * y in QR_N. This means x * y mod N.
func (group *QRSpecialRSA) Mul(x, y *big.Int) *big.Int {
	r := new(big.Int)
	r.Mul(x, y)
	return r.Mod(r, group.N)
}

// Inv computes inverse of x in QR_N. This means xInv such that x * xInv = 1 mod N.
func (group *QRSpecialRSA) Inv(x *big.Int) *big.Int {
	return new(big.Int).ModInverse(x, group.N)
}

// Exp computes base^exponent in QR_N. This means base^exponent mod rsa.N.
func (group *QRSpecialRSA) Exp(base, exponent *big.Int) *big.Int {
	return new(big.Int).Exp(base, exponent, group.N)
}

/*
TODO: use QR method when QR will be made parent
// IsElementInGroup returns true if x is in QR_N and false otherwise.
func (group *QRSpecialRSA) IsElementInGroup(x *big.Int) bool {

}
*/
