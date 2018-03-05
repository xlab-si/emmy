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

package pseudonymsys

import (
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

type SecKey struct {
	S1, S2 *big.Int
}

func NewSecKey(s1, s2 *big.Int) *SecKey {
	return &SecKey{s1, s2}
}

type PubKey struct {
	H1, H2 *big.Int
}

func NewPubKey(h1, h2 *big.Int) *PubKey {
	return &PubKey{h1, h2}
}

type PubKeyEC struct {
	H1, H2 *groups.ECGroupElement
}

func NewPubKeyEC(h1, h2 *groups.ECGroupElement) *PubKeyEC {
	return &PubKeyEC{h1, h2}
}

// GenerateKeyPair takes a schnorr group and constructs a pair of secret and public key for
// pseudonym system scheme.
func GenerateKeyPair(group *groups.SchnorrGroup) (*SecKey, *PubKey) {
	s1 := common.GetRandomInt(group.Q)
	s2 := common.GetRandomInt(group.Q)
	h1 := group.Exp(group.G, s1)
	h2 := group.Exp(group.G, s2)

	return NewSecKey(s1, s2), NewPubKey(h1, h2)
}

// GenerateECKeyPair takes EC group and constructs a public key for pseudonym system scheme in EC
// arithmetic.
func GenerateECKeyPair(group *groups.ECGroup) (*SecKey, *PubKeyEC) {
	s1 := common.GetRandomInt(group.Q)
	s2 := common.GetRandomInt(group.Q)
	h1 := group.ExpBaseG(s1)
	h2 := group.ExpBaseG(s2)

	return NewSecKey(s1, s2), NewPubKeyEC(h1, h2)
}
