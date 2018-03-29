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

// ProveECDLogKnowledge demonstrates how prover can prove the knowledge of log_g1(t1) - that
// means g1^secret = t1 in EC group.
func ProveECDLogKnowledge(secret *big.Int, g1, t1 *groups.ECGroupElement, curve groups.ECurve) (bool, error) {
	prover := NewSchnorrECProver(curve)
	verifier := NewSchnorrECVerifier(curve)

	x := prover.GetProofRandomData(secret, g1)
	verifier.SetProofRandomData(x, g1, t1)

	challenge := verifier.GetChallenge()
	z := prover.GetProofData(challenge)
	verified := verifier.Verify(z)
	return verified, nil
}

type SchnorrECProver struct {
	Group            *groups.ECGroup
	a                *groups.ECGroupElement
	secret           *big.Int
	r                *big.Int                        // ProofRandomData
}

func NewSchnorrECProver(curveType groups.ECurve) *SchnorrECProver {
	return &SchnorrECProver{
		Group: groups.NewECGroup(curveType),
	}
}

// It contains also value b = a^secret.
func (prover *SchnorrECProver) GetProofRandomData(secret *big.Int,
	a *groups.ECGroupElement) *groups.ECGroupElement {
	r := common.GetRandomInt(prover.Group.Q)
	prover.r = r
	prover.a = a
	prover.secret = secret
	x := prover.Group.Exp(a, r)
	return x
}

// It receives challenge defined by a verifier, and returns z = r + challenge * w.
func (prover *SchnorrECProver) GetProofData(challenge *big.Int) *big.Int {
	// z = r + challenge * secret
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.Group.Q)
	return z
}

type SchnorrECVerifier struct {
	Group             *groups.ECGroup
	x                 *groups.ECGroupElement
	a                 *groups.ECGroupElement
	b                 *groups.ECGroupElement
	challenge         *big.Int
}

func NewSchnorrECVerifier(curveType groups.ECurve) *SchnorrECVerifier {
	return &SchnorrECVerifier{
		Group:        groups.NewECGroup(curveType),
	}
}

// TODO: t transferred at some other stage?
func (verifier *SchnorrECVerifier) SetProofRandomData(x, a, b *groups.ECGroupElement) {
	verifier.x = x
	verifier.a = a
	verifier.b = b
}

func (verifier *SchnorrECVerifier) GetChallenge() *big.Int {
	challenge := common.GetRandomInt(verifier.Group.Q)
	verifier.challenge = challenge
	return challenge
}

func (verifier *SchnorrECVerifier) Verify(z *big.Int) bool {
	left := verifier.Group.Exp(verifier.a, z)
	r := verifier.Group.Exp(verifier.b, verifier.challenge)
	right := verifier.Group.Mul(r, verifier.x)
	return left.Equals(right)
}
