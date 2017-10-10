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

import (
	"github.com/xlab-si/emmy/crypto/common"
	"math/big"
)

// TODO: doesn't look like having the same interface for zp_dlog and ecdlog is a good idea; refactor

type ZpDLog struct {
	P               *big.Int // modulus of the group
	G               *big.Int // generator of subgroup
	OrderOfSubgroup *big.Int // order of subgroup
}

func NewZpSchnorr(qBitLength int) (*ZpDLog, error) {
	dlog := ZpDLog{}
	g, q, p, err := common.GetSchnorrGroup(qBitLength)
	dlog.G = g
	dlog.OrderOfSubgroup = q
	dlog.P = p
	return &dlog, err
}

func NewZpSafePrime(modulusBitLength int) (*ZpDLog, error) {
	p, err := common.GetSafePrime(modulusBitLength)
	if err != nil {
		return nil, err
	}
	pMin := new(big.Int)
	pMin.Sub(p, big.NewInt(1))
	q := new(big.Int).Div(pMin, big.NewInt(2))

	g, err := common.GetGeneratorOfZnSubgroup(p, pMin, q)
	if err != nil {
		return nil, err
	}

	zpSafePrime := ZpDLog{
		P:               p,
		G:               g,
		OrderOfSubgroup: q,
	}

	return &zpSafePrime, nil
}

// Multiply multiplies two elements from Z_p. Note that two values are returned
// to make it implementation of DLog interface - the second value is always nil
// (differently as in EC DLog).
func (dlog *ZpDLog) Multiply(params ...*big.Int) (*big.Int, *big.Int) {
	x := params[0]
	y := params[1]

	r := new(big.Int)
	r.Mul(x, y)
	r.Mod(r, dlog.P)

	// returning two values (second as nil) to make it implement the DLog interface sucks,
	// but other options seem even worse
	return r, nil
}

func (dlog *ZpDLog) Exponentiate(params ...*big.Int) (*big.Int, *big.Int) {
	x := params[0]
	exponent := params[1]

	r := new(big.Int)
	r.Exp(x, exponent, dlog.P)
	return r, nil
}

func (dlog *ZpDLog) ExponentiateBaseG(exponent *big.Int) (*big.Int, *big.Int) {
	x := new(big.Int)
	x.Exp(dlog.G, exponent, dlog.P)
	return x, nil
}

func (dlog *ZpDLog) Inverse(x *big.Int) *big.Int {
	inv := new(big.Int).ModInverse(x, dlog.P)
	return inv
}

func (dlog *ZpDLog) GetOrderOfSubgroup() *big.Int {
	return dlog.OrderOfSubgroup
}
