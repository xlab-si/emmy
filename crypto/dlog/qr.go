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

package dlog

// TODO: move into groups

import (
	"github.com/xlab-si/emmy/crypto/common"
	"math/big"
)

type QR struct {
	N       *big.Int // N = all factors multiplied
	Order   *big.Int
	Factors []*big.Int
}

// TODO: currently not power primes are implemented
func NewQR(factors []*big.Int) *QR {
	n := big.NewInt(1)
	order := big.NewInt(1)
	for _, p := range factors {
		n.Mul(n, p)
		pMin := new(big.Int).Sub(p, big.NewInt(1))
		order.Mul(order, pMin)
	}
	return &QR{
		N:       n,
		Order:   order,
		Factors: factors,
	}
}

func (qr *QR) Multiply(a, b *big.Int) *big.Int {
	r := new(big.Int)
	r.Mul(a, b)
	r.Mod(r, qr.N)
	return r
}

func (qr *QR) Exponentiate(a, exponent *big.Int) *big.Int {
	r := new(big.Int)
	r.Exp(a, exponent, qr.N)
	return r
}

func (qr *QR) IsQR(a *big.Int) (bool, error) {
	for _, p := range qr.Factors {
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
