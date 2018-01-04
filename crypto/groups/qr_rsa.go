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
	"errors"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
)

// QRRSA presents QR_N - group of quadratic residues modulo N where N is a product
// of two primes. This group is in general NOT cyclic (it is only when (P-1)/2 and (Q-1)/2 are primes,
// see QRSpecialRSA). The group QR_N is isomorphic to QR_P x QR_Q.
type QRRSA struct {
	N     *big.Int // N = P * Q
	P     *big.Int
	Q     *big.Int
	Order *big.Int // Order = (P-1)/2 * (Q-1)/2
}

func NewQRRSA(P, Q *big.Int) (*QRRSA, error) {
	if !P.ProbablyPrime(20) || !Q.ProbablyPrime(20) {
		return nil, errors.New("P and Q must be primes")
	}
	pMin := new(big.Int).Sub(P, big.NewInt(1))
	pMinHalf := new(big.Int).Div(pMin, big.NewInt(2))
	qMin := new(big.Int).Sub(Q, big.NewInt(1))
	qMinHalf := new(big.Int).Div(qMin, big.NewInt(2))
	order := new(big.Int).Mul(pMinHalf, qMinHalf)
	return &QRRSA{
		N:     new(big.Int).Mul(P, Q),
		P:     P,
		Q:     Q,
		Order: order,
	}, nil
}

func NewQRRSAPublic(N *big.Int) *QRRSA {
	return &QRRSA{
		N: N,
	}
}

// Mul computes x * y in QR_N. This means x * y mod N.
func (group *QRRSA) Mul(x, y *big.Int) *big.Int {
	r := new(big.Int)
	r.Mul(x, y)
	return r.Mod(r, group.N)
}

// Inv computes inverse of x in QR_N. This means xInv such that x * xInv = 1 mod N.
func (group *QRRSA) Inv(x *big.Int) *big.Int {
	return new(big.Int).ModInverse(x, group.N)
}

// Exp computes base^exponent in QR_N. This means base^exponent mod rsa.N.
func (group *QRRSA) Exp(base, exponent *big.Int) *big.Int {
	return new(big.Int).Exp(base, exponent, group.N)
}

// IsElementInGroup returns true if a is in QR_N and false otherwise.
func (group *QRRSA) IsElementInGroup(a *big.Int) (bool, error) {
	if group.P == nil {
		return false,
			errors.New("IsElementInGroup not available for QRRSA with only public parameters")
	}

	factors := []*big.Int{group.P, group.Q}
	for _, p := range factors {
		isQR, err := common.IsQuadraticResidue(a, p)
		if err != nil {
			return false, err
		}
		if !isQR {
			return false, nil
		}
	}
	return true, nil
}
