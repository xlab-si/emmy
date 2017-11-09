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

package common

import (
	"math/big"
)

// TODO: Group interface is experimental, used currently in FPreimageProver, it should be checked
// in the existing code if it makes sense to use it there.
// I would say for EC we should introduce ECGroup interface. All these should be moved
// into dlog package which should be renamed as groups.
type Group interface {
	GetRandomElement() *big.Int
	Mul(*big.Int, *big.Int) *big.Int
	Exp(*big.Int, *big.Int) *big.Int
	Inv(*big.Int) *big.Int
	IsElementInGroup(*big.Int) bool
}

type ZnGroup struct {
	N *big.Int
}

func NewZnGroup(n *big.Int) *ZnGroup {
	return &ZnGroup{
		N: n,
	}
}

func (znGroup *ZnGroup) GetRandomElement() *big.Int {
	return GetRandomZnInvertibleElement(znGroup.N)
}

func (znGroup *ZnGroup) Mul(x, y *big.Int) *big.Int {
	r := new(big.Int)
	r.Mul(x, y)
	r.Mod(r, znGroup.N)
	return r
}

func (znGroup *ZnGroup) Exp(x, exponent *big.Int) *big.Int {
	r := new(big.Int)
	r.Exp(x, exponent, znGroup.N)
	return r
}

func (znGroup *ZnGroup) Inv(x *big.Int) *big.Int {
	return new(big.Int).ModInverse(x, znGroup.N)
}

func (znGroup *ZnGroup) IsElementInGroup(x *big.Int) bool {
	c := new(big.Int).GCD(nil, nil, x, znGroup.N)
	return x.Cmp(znGroup.N) < 0 && c.Cmp(big.NewInt(1)) == 0
}
