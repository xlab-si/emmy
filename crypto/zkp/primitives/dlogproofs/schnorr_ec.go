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

package dlogproofs

import (
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

type SchnorrECProver struct {
	Group  *groups.ECGroup
	a      *groups.ECGroupElement
	secret *big.Int
	r      *big.Int // ProofRandomData
}

func NewSchnorrECProver(curveType groups.ECurve) *SchnorrECProver {
	return &SchnorrECProver{
		Group: groups.NewECGroup(curveType),
	}
}

// It contains also value b = a^secret.
func (p *SchnorrECProver) GetProofRandomData(secret *big.Int,
	a *groups.ECGroupElement) *groups.ECGroupElement {
	r := common.GetRandomInt(p.Group.Q)
	p.r = r
	p.a = a
	p.secret = secret
	x := p.Group.Exp(a, r)
	return x
}

// It receives challenge defined by a verifier, and returns z = r + challenge * w.
func (p *SchnorrECProver) GetProofData(challenge *big.Int) *big.Int {
	// z = r + challenge * secret
	z := new(big.Int)
	z.Mul(challenge, p.secret)
	z.Add(z, p.r)
	z.Mod(z, p.Group.Q)
	return z
}

type SchnorrECVerifier struct {
	Group     *groups.ECGroup
	x         *groups.ECGroupElement
	a         *groups.ECGroupElement
	b         *groups.ECGroupElement
	challenge *big.Int
}

func NewSchnorrECVerifier(curveType groups.ECurve) *SchnorrECVerifier {
	return &SchnorrECVerifier{
		Group: groups.NewECGroup(curveType),
	}
}

// TODO: t transferred at some other stage?
func (v *SchnorrECVerifier) SetProofRandomData(x, a, b *groups.ECGroupElement) {
	v.x = x
	v.a = a
	v.b = b
}

func (v *SchnorrECVerifier) GetChallenge() *big.Int {
	challenge := common.GetRandomInt(v.Group.Q)
	v.challenge = challenge
	return challenge
}

// SetChallenge is used when Fiat-Shamir is used - when challenge is generated using hash by the prover.
func (v *SchnorrECVerifier) SetChallenge(challenge *big.Int) {
	v.challenge = challenge
}

func (v *SchnorrECVerifier) Verify(z *big.Int) bool {
	left := v.Group.Exp(v.a, z)
	r := v.Group.Exp(v.b, v.challenge)
	right := v.Group.Mul(r, v.x)
	return left.Equals(right)
}
