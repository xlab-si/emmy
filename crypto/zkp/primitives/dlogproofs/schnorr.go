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

// ProveDLogKnowledge demonstrates how prover can prove the knowledge of log_g1(t1) - that
// means g1^secret = t1.
func ProveDLogKnowledge(secret, g1, t1 *big.Int, group *groups.SchnorrGroup) bool {
	prover := NewSchnorrProver(group)
	verifier := NewSchnorrVerifier(group)

	x := prover.GetProofRandomData(secret, g1)
	verifier.SetProofRandomData(x, g1, t1)

	challenge := verifier.GetChallenge()
	z := prover.GetProofData(challenge)
	verified := verifier.Verify(z)
	return verified
}

// Proving that it knows w such that g^w = h (mod p).
type SchnorrProver struct {
	Group            *groups.SchnorrGroup
	secret           *big.Int
	a                *big.Int
	r                *big.Int
}

func NewSchnorrProver(group *groups.SchnorrGroup) *SchnorrProver {
	return &SchnorrProver{
		Group:        group,
	}
}

// GetProofRandomData sets prover.secret and prover.a, and returns a^r % p where r is random.
func (prover *SchnorrProver) GetProofRandomData(secret, a *big.Int) *big.Int {
	// TODO: name GetProofRandomData is not ok, but I am not sure what would be the best way
	// to fix it.
	// It might be replaced with something that
	// would reflect setting of parameters secret and a. Splitting into two functions is
	// another option, but it would add complexity of the API (for example SetParams necessary to
	// be called before GetProofRandomData). Possible solution would also be to push secret and a
	// into SchnorrProver constructor, but then if SchnorrProver used for two different proofs
	// (two different (secret, a) pairs), its params would need to be reset before proof execution.
	// Thinking of it, this last option might be the one to go, because usually Schnorr is
	// executed once.
	// The problem is the same for all proofs.

	// x = a^r % p, where r is random
	prover.a = a
	prover.secret = secret
	r := common.GetRandomInt(prover.Group.Q)
	prover.r = r
	x := prover.Group.Exp(a, r)

	return x
}

// It receives challenge defined by a verifier and returns z = r + challenge * w.
func (prover *SchnorrProver) GetProofData(challenge *big.Int) *big.Int {
	// z = r + challenge * w
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.Group.Q)
	return z
}

type SchnorrVerifier struct {
	Group             *groups.SchnorrGroup
	x                 *big.Int
	a                 *big.Int
	b                 *big.Int
	challenge         *big.Int
}

func NewSchnorrVerifier(group *groups.SchnorrGroup) *SchnorrVerifier {
	return &SchnorrVerifier{
		Group:        group,
	}
}

// TODO: similar as described above for GetProofRandomData - this one is not setting
// only proofRandomData, thus it might be split (a, b for example set in SchnorrVerifier constructor).
func (verifier *SchnorrVerifier) SetProofRandomData(x, a, b *big.Int) {
	verifier.x = x
	verifier.a = a
	verifier.b = b
}

func (verifier *SchnorrVerifier) GetChallenge() *big.Int {
	challenge := common.GetRandomInt(verifier.Group.Q)
	verifier.challenge = challenge
	return challenge
}

// It receives y = r + w * challenge. It returns true if a^y = a^r * (a^secret) ^ challenge, otherwise false.
func (verifier *SchnorrVerifier) Verify(z *big.Int) bool {
	left := verifier.Group.Exp(verifier.a, z)
	r1 := verifier.Group.Exp(verifier.b, verifier.challenge)
	right := verifier.Group.Mul(r1, verifier.x)
	return left.Cmp(right) == 0
}
