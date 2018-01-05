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
	"crypto/elliptic"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
)

type ECurve int

const (
	P224 ECurve = 1 + iota
	P256
	P384
	P521
)

// TODO Insert appropriate comment with description of this struct
type ECGroupElement struct {
	X *big.Int
	Y *big.Int
}

func NewECGroupElement(x, y *big.Int) *ECGroupElement {
	return &ECGroupElement{
		X: x,
		Y: y,
	}
}

//TODO Is this name appropriate? Perhaps 'Equals' would be better?
func (a *ECGroupElement) Cmp(b *ECGroupElement) bool {
	return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}

// ECGroup is a wrapper around elliptic.Curve. It is a cyclic group with generator
// (c.Params().Gx, c.Params().Gy) and order c.Params().N (which is exposed as Q in a wrapper).
type ECGroup struct {
	Curve elliptic.Curve
	Q     *big.Int
}

func GetEllipticCurve(curveType ECurve) elliptic.Curve {
	switch curveType {
	case P224:
		return elliptic.P224()
	case P256:
		return elliptic.P256()
	case P384:
		return elliptic.P384()
	case P521:
		return elliptic.P521()
	}

	return elliptic.P256()
}

func NewECGroup(curveType ECurve) *ECGroup {
	c := GetEllipticCurve(curveType)
	group := ECGroup{
		Curve: c,
		Q:     c.Params().N, // order of generator G
	}
	return &group
}

// GetRandomElement returns a random element from this group.
func (group *ECGroup) GetRandomElement() *ECGroupElement {
	r := common.GetRandomInt(group.Q)
	el := group.ExpBaseG(r)
	return el
}

// Mul computes a * b in ECGroup. This actually means a + b as this is additive group.
func (group *ECGroup) Mul(a, b *ECGroupElement) *ECGroupElement {
	// computes (x1, y1) + (x2, y2) as this is group on elliptic curves
	x, y := group.Curve.Add(a.X, a.Y, b.X, b.Y)
	return NewECGroupElement(x, y)
}

// Exp computes base^exponent in ECGroup. This actually means exponent * base as this is
// additive group.
func (group *ECGroup) Exp(base *ECGroupElement, exponent *big.Int) *ECGroupElement {
	// computes (x, y) * exponent
	hx, hy := group.Curve.ScalarMult(base.X, base.Y, exponent.Bytes())
	return NewECGroupElement(hx, hy)
}

// Exp computes base^exponent in ECGroup where base is the generator.
// This actually means exponent * G as this is additive group.
func (group *ECGroup) ExpBaseG(exponent *big.Int) *ECGroupElement {
	// computes g ^^ exponent or better to say g * exponent as this is elliptic ((gx, gy) * exponent)
	hx, hy := group.Curve.ScalarBaseMult(exponent.Bytes())
	return NewECGroupElement(hx, hy)
}

// Inv computes inverse of x in ECGroup. This is done by computing x^(order-1) as:
// x * x^(order-1) = x^order = 1. Note that this actually means x * (order-1) as this is
// additive group.
func (group *ECGroup) Inv(x *ECGroupElement) *ECGroupElement {
	orderMinOne := new(big.Int).Sub(group.Q, big.NewInt(1))
	inv := group.Exp(x, orderMinOne)
	return inv
}
