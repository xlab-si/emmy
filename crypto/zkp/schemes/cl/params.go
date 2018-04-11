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

package cl

import (
	"math/big"
	"github.com/xlab-si/emmy/crypto/groups"
)

type CLParamSizes struct {
        // There are only a few possibilities for RhoBitLen. 256 implies that the modulus
        // bit length is 2048 (this number corresponds to the Gamma in idemix technical report).
	RhoBitLen int // bit length of order of the commitment group
	L_n       int // bit length of RSA modulus
	L_attrs   int // number of attributes
}

// TODO: load params from file or blockchain or wherever they will be stored.
func GetParamSizes() *CLParamSizes {
	return &CLParamSizes{
		RhoBitLen: 256,
		L_n:       1024,
		L_attrs:   3,
	}
}

type CLParams struct {
	CommitmentGroup *groups.SchnorrGroup
	CommitmentH *big.Int
}


