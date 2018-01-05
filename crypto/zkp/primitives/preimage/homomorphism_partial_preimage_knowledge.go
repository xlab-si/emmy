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

package preimage

import (
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

// ProvePartialPreimageKnowledge demonstrates how prover can prove that he knows f^(-1)(u1) and
// the verifier does not know whether knowledge of f^(-1)(u1) or f^(-1)(u2) was proved.
// Note that PartialDLogKnowledge is a special case of PartialPreimageKnowledge.
func ProveHomomorphismPartialPreimageKnowledge(homomorphism func(*big.Int) *big.Int, H groups.Group,
	v1, u1, u2 *big.Int, iterations int) bool {
	prover := NewHomomorphismPartialPreimageProver(homomorphism, H, v1, u1, u2)
	verifier := NewHomomorphismPartialPreimageVerifier(homomorphism, H)

	// The proof needs to be repeated sequentially because one-bit challenges are used. Note
	// that when one-bit challenges are used, the prover has in one iteration 50% chances
	// that guesses the challenge. Thus, sufficient number of iterations is needed (like 80).
	// One-bit challenges are required - otherwise proof of knowledge extractor might
	// not work (algorithm to extract preimage when prover is used as a black-box and
	// rewinded to use the same first message in both executions).
	for j := 0; j < iterations; j++ {
		pair1, pair2 := prover.GetProofRandomData()
		verifier.SetProofRandomData(pair1, pair2)
		challenge := verifier.GetChallenge()
		c1, z1, c2, z2 := prover.GetProofData(challenge)
		if !verifier.Verify(c1, z1, c2, z2) {
			return false
		}
	}

	return true
}

type HomomorphismPartialPreimageProver struct {
	Homomorphism func(*big.Int) *big.Int
	H            groups.Group
	v1           *big.Int
	u1           *big.Int
	u2           *big.Int
	r1           *big.Int
	c2           *big.Int
	z2           *big.Int
	ord          int
}

func NewHomomorphismPartialPreimageProver(homomorphism func(*big.Int) *big.Int, H groups.Group,
	v1, u1, u2 *big.Int) *HomomorphismPartialPreimageProver {
	return &HomomorphismPartialPreimageProver{
		Homomorphism: homomorphism,
		H:            H,
		v1:           v1,
		u1:           u1,
		u2:           u2,
	}
}

// GetProofRandomData returns Homomorphism(r1) and Homomorphism(z2)/(u2^c2)
// in random order and where r1, z2, c2 are random from H.
func (prover *HomomorphismPartialPreimageProver) GetProofRandomData() (*common.Pair, *common.Pair) {
	r1 := prover.H.GetRandomElement()
	c2 := common.GetRandomInt(big.NewInt(2)) // challenges need to be binary
	z2 := prover.H.GetRandomElement()
	prover.r1 = r1
	prover.c2 = c2
	prover.z2 = z2
	x1 := prover.Homomorphism(r1)
	x2 := prover.Homomorphism(z2)
	u2ToC2 := prover.H.Exp(prover.u2, c2)
	u2ToC2Inv := prover.H.Inv(u2ToC2)
	x2 = prover.H.Mul(x2, u2ToC2Inv)

	// we need to make sure that the order does not reveal which secret we do know:
	ord := common.GetRandomInt(big.NewInt(2))
	pair1 := common.NewPair(x1, prover.u1)
	pair2 := common.NewPair(x2, prover.u2)

	if ord.Cmp(big.NewInt(0)) == 0 {
		prover.ord = 0
		return pair1, pair2
	} else {
		prover.ord = 1
		return pair2, pair1
	}
}

func (prover *HomomorphismPartialPreimageProver) GetProofData(challenge *big.Int) (*big.Int, *big.Int,
	*big.Int, *big.Int) {
	c1 := new(big.Int).Xor(prover.c2, challenge)
	// z1 = r*v^e
	z1 := prover.H.Exp(prover.v1, c1)
	z1 = prover.H.Mul(prover.r1, z1)

	if prover.ord == 0 {
		return c1, z1, prover.c2, prover.z2
	} else {
		return prover.c2, prover.z2, c1, z1
	}
}

type HomomorphismPartialPreimageVerifier struct {
	Homomorphism func(*big.Int) *big.Int
	H            groups.Group
	pair1        *common.Pair
	pair2        *common.Pair
	challenge    *big.Int
}

func NewHomomorphismPartialPreimageVerifier(homomorphism func(*big.Int) *big.Int,
	H groups.Group) *HomomorphismPartialPreimageVerifier {
	return &HomomorphismPartialPreimageVerifier{
		Homomorphism: homomorphism,
		H:            H,
	}
}

func (verifier *HomomorphismPartialPreimageVerifier) SetProofRandomData(pair1, pair2 *common.Pair) {
	verifier.pair1 = pair1
	verifier.pair2 = pair2
}

func (verifier *HomomorphismPartialPreimageVerifier) GetChallenge() *big.Int {
	challenge := common.GetRandomInt(big.NewInt(2)) // challenges need to be binary
	verifier.challenge = challenge
	return challenge
}

func (verifier *HomomorphismPartialPreimageVerifier) verifyPair(pair *common.Pair,
	challenge, z *big.Int) bool {
	left := verifier.Homomorphism(z)
	r1 := verifier.H.Exp(pair.B, challenge)
	right := verifier.H.Mul(r1, pair.A)
	return left.Cmp(right) == 0
}

func (verifier *HomomorphismPartialPreimageVerifier) Verify(c1, z1, c2, z2 *big.Int) bool {
	c := new(big.Int).Xor(c1, c2)
	if c.Cmp(verifier.challenge) != 0 {
		return false
	}

	verified1 := verifier.verifyPair(verifier.pair1, c1, z1)
	verified2 := verifier.verifyPair(verifier.pair2, c2, z2)
	return verified1 && verified2
}
