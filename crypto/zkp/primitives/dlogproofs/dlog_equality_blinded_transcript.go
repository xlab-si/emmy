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

type Transcript struct {
	A      *big.Int
	B      *big.Int
	Hash   *big.Int
	ZAlpha *big.Int
}

func NewTranscript(a, b, hash, zAlpha *big.Int) *Transcript {
	return &Transcript{
		A:      a,
		B:      b,
		Hash:   hash,
		ZAlpha: zAlpha,
	}
}

// Verifies that the blinded transcript is valid. That means the knowledge of log_g1(t1), log_G2(T2)
// and log_g1(t1) = log_G2(T2). Note that G2 = g2^gamma, T2 = t2^gamma where gamma was chosen
// by verifier.
func VerifyBlindedTranscript(transcript *Transcript, group *groups.SchnorrGroup, g1, t1, G2, T2 *big.Int) bool {
	// Transcript should be in the following form: [alpha1, beta1, hash(alpha1, beta1), z+alpha]

	// check hash:
	hashNum := common.Hash(transcript.A, transcript.B)
	if hashNum.Cmp(transcript.Hash) != 0 {
		return false
	}

	// We need to verify (note that c-beta = hash(alpha1, beta1))
	// g1^(z+alpha) = alpha1 * t1^(c-beta)
	// G2^(z+alpha) = beta1 * T2^(c-beta)
	left1 := group.Exp(g1, transcript.ZAlpha)
	right1 := group.Exp(t1, transcript.Hash)
	right1 = group.Mul(transcript.A, right1)

	left2 := group.Exp(G2, transcript.ZAlpha)
	right2 := group.Exp(T2, transcript.Hash)
	right2 = group.Mul(transcript.B, right2)

	if left1.Cmp(right1) == 0 && left2.Cmp(right2) == 0 {
		return true
	} else {
		return false
	}
}

type DLogEqualityBTranscriptProver struct {
	Group  *groups.SchnorrGroup
	r      *big.Int
	secret *big.Int
	g1     *big.Int
	g2     *big.Int
}

func NewDLogEqualityBTranscriptProver(group *groups.SchnorrGroup) *DLogEqualityBTranscriptProver {
	prover := DLogEqualityBTranscriptProver{
		Group: group,
	}
	return &prover
}

// Prove that you know dlog_g1(h1), dlog_g2(h2) and that dlog_g1(h1) = dlog_g2(h2).
func (prover *DLogEqualityBTranscriptProver) GetProofRandomData(secret, g1, g2 *big.Int) (*big.Int,
	*big.Int) {
	// Set the values that are needed before the protocol can be run.
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

func (prover *DLogEqualityBTranscriptProver) GetProofData(challenge *big.Int) *big.Int {
	// z = r + challenge * secret
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.Group.Q)
	return z
}

type DLogEqualityBTranscriptVerifier struct {
	Group      *groups.SchnorrGroup
	gamma      *big.Int
	challenge  *big.Int
	g1         *big.Int
	g2         *big.Int
	x1         *big.Int
	x2         *big.Int
	t1         *big.Int
	t2         *big.Int
	alpha      *big.Int
	transcript *Transcript
}

func NewDLogEqualityBTranscriptVerifier(group *groups.SchnorrGroup,
	gamma *big.Int) *DLogEqualityBTranscriptVerifier {
	if gamma == nil {
		gamma = common.GetRandomInt(group.Q)
	}
	verifier := DLogEqualityBTranscriptVerifier{
		Group: group,
		gamma: gamma,
	}

	return &verifier
}

func (verifier *DLogEqualityBTranscriptVerifier) GetChallenge(g1, g2, t1, t2, x1, x2 *big.Int) *big.Int {
	// Set the values that are needed before the protocol can be run.
	// The protocol proves the knowledge of log_g1(t1), log_g2(t2) and
	// that log_g1(t1) = log_g2(t2).
	verifier.g1 = g1
	verifier.g2 = g2
	verifier.t1 = t1
	verifier.t2 = t2

	// Set the values g1^r1 and g2^r2.
	verifier.x1 = x1
	verifier.x2 = x2

	alpha := common.GetRandomInt(verifier.Group.Q)
	beta := common.GetRandomInt(verifier.Group.Q)

	// alpha1 = g1^r * g1^alpha * t1^beta
	// beta1 = (g2^r * g2^alpha * t2^beta)^gamma
	alpha1 := verifier.Group.Exp(verifier.g1, alpha)
	alpha1 = verifier.Group.Mul(verifier.x1, alpha1)
	tmp := verifier.Group.Exp(verifier.t1, beta)
	alpha1 = verifier.Group.Mul(alpha1, tmp)

	beta1 := verifier.Group.Exp(verifier.g2, alpha)
	beta1 = verifier.Group.Mul(verifier.x2, beta1)
	tmp = verifier.Group.Exp(verifier.t2, beta)
	beta1 = verifier.Group.Mul(beta1, tmp)
	beta1 = verifier.Group.Exp(beta1, verifier.gamma)

	// c = hash(alpha1, beta) + beta mod q
	hashNum := common.Hash(alpha1, beta1)
	challenge := new(big.Int).Add(hashNum, beta)
	challenge.Mod(challenge, verifier.Group.Q)

	verifier.challenge = challenge
	verifier.transcript = NewTranscript(alpha1, beta1, hashNum, nil)
	verifier.alpha = alpha

	return challenge
}

// It receives z = r + secret * challenge.
//It returns true if g1^z = g1^r * (g1^secret) ^ challenge and g2^z = g2^r * (g2^secret) ^ challenge.
func (verifier *DLogEqualityBTranscriptVerifier) Verify(z *big.Int) (bool, *Transcript,
	*big.Int, *big.Int) {
	left1 := verifier.Group.Exp(verifier.g1, z)
	left2 := verifier.Group.Exp(verifier.g2, z)

	r11 := verifier.Group.Exp(verifier.t1, verifier.challenge)
	r12 := verifier.Group.Exp(verifier.t2, verifier.challenge)
	right1 := verifier.Group.Mul(r11, verifier.x1)
	right2 := verifier.Group.Mul(r12, verifier.x2)

	// transcript [(alpha1, beta1), hash(alpha1, beta1), z+alpha]
	// however, we are actually returning [alpha1, beta1, hash(alpha1, beta1), z+alpha]
	z1 := new(big.Int).Add(z, verifier.alpha)
	verifier.transcript.ZAlpha = z1

	G2 := verifier.Group.Exp(verifier.g2, verifier.gamma)
	T2 := verifier.Group.Exp(verifier.t2, verifier.gamma)

	if left1.Cmp(right1) == 0 && left2.Cmp(right2) == 0 {
		return true, verifier.transcript, G2, T2
	} else {
		return false, nil, nil, nil
	}
}
