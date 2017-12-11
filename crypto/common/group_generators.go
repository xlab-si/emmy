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
	"errors"
	"math/big"
)

// GetGeneratorOfZnSubgroup returns a generator of a subgroup of a specified order in Z_n.
// Parameter groupOrder is order of Z_n (if n is prime, order is n-1).
func GetGeneratorOfZnSubgroup(n, groupOrder, subgroupOrder *big.Int) (*big.Int, error) {
	if big.NewInt(0).Mod(groupOrder, subgroupOrder).Cmp(big.NewInt(0)) != 0 {
		err := errors.New("subgroupOrder does not divide groupOrder")
		return nil, err
	}
	r := new(big.Int).Div(groupOrder, subgroupOrder)
	for {
		h := GetRandomInt(n)
		g := new(big.Int)
		g.Exp(h, r, n)
		if g.Cmp(big.NewInt(1)) != 0 {
			return g, nil
		}
	}
}
