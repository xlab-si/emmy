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

// TODO: move qrproofs, pseudonymsys and dlogproofs into zkp

import (
	"github.com/xlab-si/emmy/crypto/common"
	"math/big"
)

// ProvePreimageKnowledge demonstrates how given homomorphism f:H->G and element u from G
// prover can prove the knowledge of v such that f(v) = u.
func ProvePreimageKnowledge(homomorphism func(*big.Int) *big.Int, H common.Group,
	challengeMax, u, v *big.Int) bool {
	prover := NewFPreimageProver(homomorphism, H, v)
	proofRandomData := prover.GetProofRandomData()

	verifier := NewFPreimageVerifier(homomorphism, H, challengeMax, u)
	verifier.SetProofRandomData(proofRandomData)
	challenge := verifier.GetChallenge()

	z := prover.GetProofData(challenge)
	proved := verifier.Verify(z)

	return proved
}

// Given q-one-way homomorphism f: H -> G and u from group G, we want to prove that
// we know v such that f(v) = u. This is generalized Schnorr prover where QOneWayHomomorphism(x)
// would be g^x mod N.
type FPreimageProver struct {
	QOneWayHomomorphism func(*big.Int) *big.Int
	H                   common.Group
	v                   *big.Int
	r                   *big.Int
}

func NewFPreimageProver(homomorphism func(*big.Int) *big.Int, H common.Group, v *big.Int) *FPreimageProver {
	return &FPreimageProver{
		QOneWayHomomorphism: homomorphism,
		H:                   H,
		v:                   v,
	}
}

// Chooses random r from H and returns QOneWayHomomorpism(r).
func (prover *FPreimageProver) GetProofRandomData() *big.Int {
	// TODO: see SchnorrProver comment, note that here setting of the required parameters (v) is
	// done in the constructor.

	// x = QOneWayHomomorphism(r), where r is random
	r := prover.H.GetRandomElement()
	prover.r = r
	x := prover.QOneWayHomomorphism(r)
	return x
}

// GetProofData receives challenge defined by a verifier, and returns z = r * v^challenge.
func (prover *FPreimageProver) GetProofData(challenge *big.Int) *big.Int {
	// z = r * v^challenge
	z := prover.H.Exp(prover.v, challenge)
	z = prover.H.Mul(prover.r, z)
	return z
}

type FPreimageVerifier struct {
	QOneWayHomomorphism func(*big.Int) *big.Int
	H                   common.Group
	ChallengeMax        *big.Int
	challenge           *big.Int
	u                   *big.Int
	x                   *big.Int
}

func NewFPreimageVerifier(homomorphism func(*big.Int) *big.Int, H common.Group,
	challengeMax *big.Int, u *big.Int) *FPreimageVerifier {
	return &FPreimageVerifier{
		QOneWayHomomorphism: homomorphism,
		H:                   H,
		ChallengeMax:        challengeMax,
		u:                   u,
	}
}

func (verifier *FPreimageVerifier) SetProofRandomData(x *big.Int) {
	verifier.x = x
}

func (verifier *FPreimageVerifier) GetChallenge() *big.Int {
	challenge := common.GetRandomInt(verifier.ChallengeMax)
	verifier.challenge = challenge
	return challenge
}

// It receives z = r * v^challenge. It returns true if QOneWayHomomorphism(z) = x * u^challenge, otherwise false.
func (verifier *FPreimageVerifier) Verify(z *big.Int) bool {
	left := verifier.QOneWayHomomorphism(z)
	right := verifier.H.Exp(verifier.u, verifier.challenge)
	right = verifier.H.Mul(verifier.x, right)
	return left.Cmp(right) == 0
}
