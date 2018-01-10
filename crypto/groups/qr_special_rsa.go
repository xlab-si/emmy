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

// TODO: check group_generators.go and move the content into groups

import (
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
)

// QRSpecialRSA presents QR_N - group of quadratic residues modulo N where N is a product
// of two SAFE primes. This group is cyclic and a generator is easy to find.
// The group QR_N is isomorphic to QR_P x QR_Q. The order of QR_P and QR_Q are
// P1 and Q1 respectively. Because gcd(P1, Q1) = 1, QR_P x QR_Q is cyclic as well.
type QRSpecialRSA struct {
	QRRSA          // make QRRSA a parent to have an access to Mul, Exp, Inv, IsQR
	N     *big.Int // N = P * Q, P = 2*P1 + 1, Q = 2*Q1 + 1
	P     *big.Int
	Q     *big.Int
	P1    *big.Int
	Q1    *big.Int
	Order *big.Int // order of group QR_N (it is P1 * Q1)
}

func NewQRSpecialRSA(safePrimeBitLength int) (*QRSpecialRSA, error) {
	specialRSAPrimes, err := common.GetSpecialRSAPrimes(safePrimeBitLength)
	if err != nil {
		return nil, err
	}

	qrRSA, err := NewQRRSA(specialRSAPrimes.P, specialRSAPrimes.Q)
	if err != nil {
		return nil, err
	}
	return &QRSpecialRSA{
		N:     qrRSA.N,
		P:     specialRSAPrimes.P,
		Q:     specialRSAPrimes.Q,
		P1:    specialRSAPrimes.P1,
		Q1:    specialRSAPrimes.Q1,
		Order: qrRSA.Order,
		QRRSA: *qrRSA,
	}, nil
}

func NewQRSpecialRSAPublic(N *big.Int) *QRSpecialRSA {
	return &QRSpecialRSA{
		N:     N,
		QRRSA: *NewQRRSAPublic(N),
	}
}

// GetRandomGenerator returns a random generator of a group of quadratic residues QR_N.
func (group *QRSpecialRSA) GetRandomGenerator() (*big.Int, error) {
	// We know Z_n* and Z_p* x Z_q* are isomorphic (Chinese Remainder Theorem).
	// Let's take x from Z_n* and its counterpart from (x mod p, x mod q) from Z_p* x Z_q*.
	// Because of the isomorphism, if we compute x^2 mod n, the counterpart of this
	// element in Z_p* x Z_q* is (x^2 mod p, x^2 mod q).
	// Thus QR_n = QR_p x QR_q.
	// The order of QR_p is (p-1)/2 = p1 and the order of QR_q is (q-1)/2 = q1.
	// Because p1 and q1 are primes, QR_p and QR_q are cyclic. Thus, also QR_n is cyclic
	// (because the product of two cyclic groups is cyclic iff the two orders are coprime)
	// and of order p1 * q1.
	// Thus the possible orders of elements in QR_n are: p1, q1, p1 * q1.
	// We need to find an element of order p1 * q1 (we rule out elements of order p1 and q1).

	if group.P == nil {
		return nil,
			fmt.Errorf("GetRandomGenerator not available for QRSpecialRSA with only public parameters")
	}

	for {
		a := common.GetRandomZnInvertibleElement(group.N)
		a.Exp(a, big.NewInt(2), group.N) // make it quadratic residue

		// check if the order is p1
		check1 := group.Exp(a, group.P1)
		if check1.Cmp(big.NewInt(1)) == 0 {
			continue
		}

		// check if the order is q1
		check2 := group.Exp(a, group.Q1)
		if check2.Cmp(big.NewInt(1)) == 0 {
			continue
		}

		return a, nil
	}
}

// GetRandomElement returns a random element from this group. First a random generator
// is chosen and then it is exponentiated to the random int between 0 and order
// of QR_N (P1 * Q1).
func (group *QRSpecialRSA) GetRandomElement() (*big.Int, error) {
	if group.P == nil {
		return nil,
			fmt.Errorf("GetRandomElement not available for QRSpecialRSA with only public parameters")
	}
	g, err := group.GetRandomGenerator()
	if err != nil {
		return nil, err
	}
	r := common.GetRandomInt(group.Order)
	el := group.Exp(g, r)
	return el, nil
}
