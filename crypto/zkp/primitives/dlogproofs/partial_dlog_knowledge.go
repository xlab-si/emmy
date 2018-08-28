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
	"github.com/xlab-si/emmy/crypto/schnorr"
)

// ProvePartialDLogKnowledge demonstrates how prover can prove that he knows dlog_a2(b2) and
// the verifier does not know whether knowledge of dlog_a1(b1) or knowledge of dlog_a2(b2) was proved.
func ProvePartialDLogKnowledge(group *schnorr.Group, secret1, a1, a2, b2 *big.Int) bool {
	prover := NewPartialDLogProver(group)
	verifier := NewPartialDLogVerifier(group)

	b1 := prover.Group.Exp(a1, secret1)
	triple1, triple2 := prover.GetProofRandomData(secret1, a1, b1, a2, b2)

	verifier.SetProofRandomData(triple1, triple2)
	challenge := verifier.GetChallenge()

	c1, z1, c2, z2 := prover.GetProofData(challenge)
	verified := verifier.Verify(c1, z1, c2, z2)
	return verified
}

// Proving that it knows either secret1 such that a1^secret1 = b1 (mod p1) or
//  secret2 such that a2^secret2 = b2 (mod p2).
type PartialDLogProver struct {
	Group   *schnorr.Group
	secret1 *big.Int
	a1      *big.Int
	a2      *big.Int
	r1      *big.Int
	c2      *big.Int
	z2      *big.Int
	ord     int
}

func NewPartialDLogProver(group *schnorr.Group) *PartialDLogProver {
	return &PartialDLogProver{
		Group: group,
	}
}

func (prover *PartialDLogProver) GetProofRandomData(secret1, a1, b1, a2,
	b2 *big.Int) (*common.Triple, *common.Triple) {
	prover.a1 = a1
	prover.a2 = a2
	prover.secret1 = secret1
	r1 := common.GetRandomInt(prover.Group.Q)
	c2 := common.GetRandomInt(prover.Group.Q)
	z2 := common.GetRandomInt(prover.Group.Q)
	prover.r1 = r1
	prover.c2 = c2
	prover.z2 = z2
	x1 := prover.Group.Exp(a1, r1)
	x2 := prover.Group.Exp(a2, z2)
	b2ToC2 := prover.Group.Exp(b2, c2)
	b2ToC2Inv := prover.Group.Inv(b2ToC2)
	x2 = prover.Group.Mul(x2, b2ToC2Inv)

	// we need to make sure that the order does not reveal which secret we do know:
	ord := common.GetRandomInt(big.NewInt(2))
	triple1 := common.NewTriple(x1, a1, b1)
	triple2 := common.NewTriple(x2, a2, b2)

	if ord.Cmp(big.NewInt(0)) == 0 {
		prover.ord = 0
		return triple1, triple2
	} else {
		prover.ord = 1
		return triple2, triple1
	}
}

func (prover *PartialDLogProver) GetProofData(challenge *big.Int) (*big.Int, *big.Int,
	*big.Int, *big.Int) {
	c1 := new(big.Int).Xor(prover.c2, challenge)

	z1 := new(big.Int)
	z1.Mul(c1, prover.secret1)
	z1.Add(z1, prover.r1)
	z1.Mod(z1, prover.Group.Q)

	if prover.ord == 0 {
		return c1, z1, prover.c2, prover.z2
	} else {
		return prover.c2, prover.z2, c1, z1
	}
}

type PartialDLogVerifier struct {
	Group     *schnorr.Group
	triple1   *common.Triple // contains x1, a1, b1
	triple2   *common.Triple // contains x2, a2, b2
	challenge *big.Int
}

func NewPartialDLogVerifier(group *schnorr.Group) *PartialDLogVerifier {
	return &PartialDLogVerifier{
		Group: group,
	}
}

func (verifier *PartialDLogVerifier) SetProofRandomData(triple1, triple2 *common.Triple) {
	verifier.triple1 = triple1
	verifier.triple2 = triple2
}

func (verifier *PartialDLogVerifier) GetChallenge() *big.Int {
	challenge := common.GetRandomInt(verifier.Group.Q)
	verifier.challenge = challenge
	return challenge
}

func (verifier *PartialDLogVerifier) verifyTriple(triple *common.Triple,
	challenge, z *big.Int) bool {
	left := verifier.Group.Exp(triple.B, z)       // (a, z)
	r1 := verifier.Group.Exp(triple.C, challenge) // (b, challenge)
	right := verifier.Group.Mul(r1, triple.A)     // (r1, x1)

	return left.Cmp(right) == 0
}

func (verifier *PartialDLogVerifier) Verify(c1, z1, c2, z2 *big.Int) bool {
	c := new(big.Int).Xor(c1, c2)
	if c.Cmp(verifier.challenge) != 0 {
		return false
	}

	verified1 := verifier.verifyTriple(verifier.triple1, c1, z1)
	verified2 := verifier.verifyTriple(verifier.triple2, c2, z2)
	return verified1 && verified2
}
