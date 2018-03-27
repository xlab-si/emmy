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

package proto

import (
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

type PbConvertibleType interface {
	GetNativeType() interface{}
}

func (el *ECGroupElement) GetNativeType() *groups.ECGroupElement {
	return &groups.ECGroupElement{
		X: new(big.Int).SetBytes(el.X),
		Y: new(big.Int).SetBytes(el.Y),
	}
}

func ToPbECGroupElement(el *groups.ECGroupElement) *ECGroupElement {
	x := ECGroupElement{X: el.X.Bytes(), Y: el.Y.Bytes()}
	return &x
}

func (el *Pair) GetNativeType() *common.Pair {
	return &common.Pair{
		A: new(big.Int).SetBytes(el.A),
		B: new(big.Int).SetBytes(el.B),
	}
}

func ToPbPair(el *common.Pair) *Pair {
	return &Pair{
		A: el.A.Bytes(),
		B: el.B.Bytes(),
	}
}
