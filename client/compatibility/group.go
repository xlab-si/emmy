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

package compatibility

import (
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/groups"
)

// SchnorrGroup represents an equivalent of groups.SchnorrGroup, but has string
// field types to overcome type restrictions of Go language binding tools.
type SchnorrGroup struct {
	P string
	G string
	Q string
}

func NewSchnorrGroup(p, g, q string) *SchnorrGroup {
	return &SchnorrGroup{
		P: p,
		G: g,
		Q: q,
	}
}

func (sg *SchnorrGroup) toNativeType() (*groups.SchnorrGroup, error) {
	p, pOk := new(big.Int).SetString(sg.P, 10)
	g, gOk := new(big.Int).SetString(sg.G, 10)
	q, qOk := new(big.Int).SetString(sg.Q, 10)

	if !pOk || !gOk || !qOk {
		return nil, fmt.Errorf("groups's p, g or q: %s", ArgsConversionError)
	}

	group := groups.NewSchnorrGroupFromParams(p, g, q)
	return group, nil
}
