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
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"math/big"
)

// ProveDLogEquality demonstrates how prover can prove the knowledge of log_g1(t1), log_g2(t2) and
// that log_g1(t1) = log_g2(t2).
func ProveDLogEquality(secret, g1, g2, t1, t2 *big.Int, group *groups.SchnorrGroup) bool {
	eProver := NewDLogEqualityProver(group)
	eVerifier := NewDLogEqualityVerifier(group)

	x1, x2 := eProver.GetProofRandomData(secret, g1, g2)

	challenge := eVerifier.GetChallenge(g1, g2, t1, t2, x1, x2)
	z := eProver.GetProofData(challenge)
	verified := eVerifier.Verify(z)
	return verified
}

type DLogEqualityProver struct {
	Group  *groups.SchnorrGroup
	r      *big.Int
	secret *big.Int
	g1     *big.Int
	g2     *big.Int
}

func NewDLogEqualityProver(group *groups.SchnorrGroup) *DLogEqualityProver {
	prover := DLogEqualityProver{
		Group: group,
	}

	return &prover
}

func (prover *DLogEqualityProver) GetProofRandomData(secret, g1, g2 *big.Int) (*big.Int, *big.Int) {
	// Sets the values that are needed before the protocol can be run.
	// The protocol proves the knowledge of log_g1(t1), log_g2(t2) and
	// that log_g1(t1) = log_g2(t2).
	prover.secret = secret
	prover.g1 = g1
	prover.g2 = g2

	r := common.GetRandomInt(prover.Group.Q)
	prover.r = r
	x1 := prover.Group.Exp(prover.g1, r)
	x2 := prover.Group.Exp(prover.g2, r)
	return x1, x2
}

func (prover *DLogEqualityProver) GetProofData(challenge *big.Int) *big.Int {
	// z = r + challenge * secret
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.Group.Q)
	return z
}

type DLogEqualityVerifier struct {
	Group     *groups.SchnorrGroup
	challenge *big.Int
	g1        *big.Int
	g2        *big.Int
	x1        *big.Int
	x2        *big.Int
	t1        *big.Int
	t2        *big.Int
}

func NewDLogEqualityVerifier(group *groups.SchnorrGroup) *DLogEqualityVerifier {
	verifier := DLogEqualityVerifier{
		Group: group,
	}

	return &verifier
}

func (verifier *DLogEqualityVerifier) GetChallenge(g1, g2, t1, t2, x1, x2 *big.Int) *big.Int {
	// Set the values that are needed before the protocol can be run.
	// The protocol proves the knowledge of log_g1(t1), log_g2(t2) and
	// that log_g1(t1) = log_g2(t2).
	verifier.g1 = g1
	verifier.g2 = g2
	verifier.t1 = t1
	verifier.t2 = t2

	// Sets the values g1^r1 and g2^r2.
	verifier.x1 = x1
	verifier.x2 = x2

	challenge := common.GetRandomInt(verifier.Group.Q)
	verifier.challenge = challenge
	return challenge
}

// It receives z = r + secret * challenge.
//It returns true if g1^z = g1^r * (g1^secret) ^ challenge and g2^z = g2^r * (g2^secret) ^ challenge.
func (verifier *DLogEqualityVerifier) Verify(z *big.Int) bool {
	left1 := verifier.Group.Exp(verifier.g1, z)
	left2 := verifier.Group.Exp(verifier.g2, z)

	r11 := verifier.Group.Exp(verifier.t1, verifier.challenge)
	r12 := verifier.Group.Exp(verifier.t2, verifier.challenge)
	right1 := verifier.Group.Mul(r11, verifier.x1)
	right2 := verifier.Group.Mul(r12, verifier.x2)

	if left1.Cmp(right1) == 0 && left2.Cmp(right2) == 0 {
		return true
	} else {
		return false
	}
}
