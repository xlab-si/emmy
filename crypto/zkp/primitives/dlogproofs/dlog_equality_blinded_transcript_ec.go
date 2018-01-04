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
	"github.com/xlab-si/emmy/types"
)

// Verifies that the blinded transcript is valid. That means the knowledge of log_g1(t1), log_G2(T2)
// and log_g1(t1) = log_G2(T2). Note that G2 = g2^gamma, T2 = t2^gamma where gamma was chosen
// by verifier.
func VerifyBlindedTranscriptEC(transcript *TranscriptEC, curve groups.ECurve,
	g1, t1, G2, T2 *types.ECGroupElement) bool {
	group := groups.NewECGroup(curve)

	// check hash:
	hashNum := common.Hash(transcript.Alpha_1, transcript.Alpha_2,
		transcript.Beta_1, transcript.Beta_2)
	if hashNum.Cmp(transcript.Hash) != 0 {
		return false
	}

	// We need to verify (note that c-beta = hash(alpha11, alpha12, beta11, beta12))
	// g1^(z+alpha) = (alpha11, alpha12) * t1^(c-beta)
	// G2^(z+alpha) = (beta11, beta12) * T2^(c-beta)
	left1 := group.Exp(g1, transcript.ZAlpha)
	right1 := group.Exp(t1, transcript.Hash)
	Alpha := types.NewECGroupElement(transcript.Alpha_1, transcript.Alpha_2)
	right1 = group.Mul(Alpha, right1)

	left2 := group.Exp(G2, transcript.ZAlpha)
	right2 := group.Exp(T2, transcript.Hash)
	Beta := types.NewECGroupElement(transcript.Beta_1, transcript.Beta_2)
	right2 = group.Mul(Beta, right2)

	return types.CmpECGroupElements(left1, right1) && types.CmpECGroupElements(left2, right2)
}

type TranscriptEC struct {
	Alpha_1 *big.Int
	Alpha_2 *big.Int
	Beta_1  *big.Int
	Beta_2  *big.Int
	Hash    *big.Int
	ZAlpha  *big.Int
}

func NewTranscriptEC(alpha_1, alpha_2, beta_1, beta_2, hash, zAlpha *big.Int) *TranscriptEC {
	return &TranscriptEC{
		Alpha_1: alpha_1,
		Alpha_2: alpha_2,
		Beta_1:  beta_1,
		Beta_2:  beta_2,
		Hash:    hash,
		ZAlpha:  zAlpha,
	}
}

type ECDLogEqualityBTranscriptProver struct {
	Group  *groups.ECGroup
	r      *big.Int
	secret *big.Int
	g1     *types.ECGroupElement
	g2     *types.ECGroupElement
}

func NewECDLogEqualityBTranscriptProver(curve groups.ECurve) *ECDLogEqualityBTranscriptProver {
	group := groups.NewECGroup(curve)
	prover := ECDLogEqualityBTranscriptProver{
		Group: group,
	}
	return &prover
}

// Prove that you know dlog_g1(h1), dlog_g2(h2) and that dlog_g1(h1) = dlog_g2(h2).
func (prover *ECDLogEqualityBTranscriptProver) GetProofRandomData(secret *big.Int,
	g1, g2 *types.ECGroupElement) (*types.ECGroupElement, *types.ECGroupElement) {
	// Set the values that are needed before the protocol can be run.
	// The protocol proves the knowledge of log_g1(t1), log_g2(t2) and
	// that log_g1(t1) = log_g2(t2).
	prover.secret = secret
	prover.g1 = g1
	prover.g2 = g2

	r := common.GetRandomInt(prover.Group.Q)
	prover.r = r
	a := prover.Group.Exp(prover.g1, r)
	b := prover.Group.Exp(prover.g2, r)
	return a, b
}

func (prover *ECDLogEqualityBTranscriptProver) GetProofData(challenge *big.Int) *big.Int {
	// z = r + challenge * secret
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.Group.Q)
	return z
}

type ECDLogEqualityBTranscriptVerifier struct {
	Group      *groups.ECGroup
	gamma      *big.Int
	challenge  *big.Int
	g1         *types.ECGroupElement
	g2         *types.ECGroupElement
	x1         *types.ECGroupElement
	x2         *types.ECGroupElement
	t1         *types.ECGroupElement
	t2         *types.ECGroupElement
	alpha      *big.Int
	transcript *TranscriptEC
}

func NewECDLogEqualityBTranscriptVerifier(curve groups.ECurve,
	gamma *big.Int) *ECDLogEqualityBTranscriptVerifier {
	group := groups.NewECGroup(curve)
	if gamma == nil {
		gamma = common.GetRandomInt(group.Q)
	}
	verifier := ECDLogEqualityBTranscriptVerifier{
		Group: group,
		gamma: gamma,
	}

	return &verifier
}

func (verifier *ECDLogEqualityBTranscriptVerifier) GetChallenge(g1, g2, t1, t2, x1,
	x2 *types.ECGroupElement) *big.Int {
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
	hashNum := common.Hash(alpha1.X, alpha1.Y, beta1.X, beta1.Y)
	challenge := new(big.Int).Add(hashNum, beta)
	challenge.Mod(challenge, verifier.Group.Q)

	verifier.challenge = challenge
	verifier.transcript = NewTranscriptEC(alpha1.X, alpha1.Y, beta1.X, beta1.Y, hashNum, nil)
	verifier.alpha = alpha

	return challenge
}

// It receives z = r + secret * challenge.
//It returns true if g1^z = g1^r * (g1^secret) ^ challenge and g2^z = g2^r * (g2^secret) ^ challenge.
func (verifier *ECDLogEqualityBTranscriptVerifier) Verify(z *big.Int) (bool, *TranscriptEC,
	*types.ECGroupElement, *types.ECGroupElement) {
	left1 := verifier.Group.Exp(verifier.g1, z)
	left2 := verifier.Group.Exp(verifier.g2, z)

	r1 := verifier.Group.Exp(verifier.t1, verifier.challenge)
	r2 := verifier.Group.Exp(verifier.t2, verifier.challenge)
	right1 := verifier.Group.Mul(r1, verifier.x1)
	right2 := verifier.Group.Mul(r2, verifier.x2)

	// transcript [(alpha11, alpha12, beta11, beta12), hash(alpha11, alpha12, beta11, beta12), z+alpha]
	// however, we are actually returning:
	// [alpha11, alpha12, beta11, beta12, hash(alpha11, alpha12, beta11, beta12), z+alpha]
	z1 := new(big.Int).Add(z, verifier.alpha)
	verifier.transcript.ZAlpha = z1

	G2 := verifier.Group.Exp(verifier.g2, verifier.gamma)
	T2 := verifier.Group.Exp(verifier.t2, verifier.gamma)

	if types.CmpECGroupElements(left1, right1) && types.CmpECGroupElements(left2, right2) {
		return true, verifier.transcript, G2, T2
	} else {
		return false, nil, nil, nil
	}
}
