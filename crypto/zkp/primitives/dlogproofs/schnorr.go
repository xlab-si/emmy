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
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

// SchnorrProver is a generalized Schnorr - while usually Schnorr proof is executed with one base,
// SchnorrProver for a given y enables proof of knowledge of secrets x_1,...,x_k
// such that y = g_1^x_1 * ... * g_k^x_k where g_i are given generators (bases) of cyclic group G.
// For a "normal" Schnorr just use bases and secrets arrays with only one element.
type SchnorrProver struct {
	Group        *groups.SchnorrGroup
	secrets      []*big.Int
	bases        []*big.Int
	randomValues []*big.Int
	y            *big.Int
}

func NewSchnorrProver(group *groups.SchnorrGroup, secrets,
	bases []*big.Int, y *big.Int) (*SchnorrProver, error) {
	if len(secrets) != len(bases) {
		return nil, fmt.Errorf("number of secrets and representation bases shoud be the same")
	}

	return &SchnorrProver{
		Group:   group,
		secrets: secrets,
		bases:   bases,
		y:       y,
	}, nil
}

func (prover *SchnorrProver) GetProofRandomData() *big.Int {
	// t = g_1^r_1 * ... * g_k^r_k where g_i are bases and r_i are random values
	t := big.NewInt(1)
	var randomValues []*big.Int
	for i := 0; i < len(prover.bases); i++ {
		r := common.GetRandomInt(prover.Group.Q)
		randomValues = append(randomValues, r)
		f := prover.Group.Exp(prover.bases[i], r)
		t = prover.Group.Mul(t, f)
	}
	prover.randomValues = randomValues
	return t
}

func (prover *SchnorrProver) GetProofData(challenge *big.Int) []*big.Int {
	// z_i = r_i + challenge * secrets[i]
	var proofData []*big.Int
	for i := 0; i < len(prover.bases); i++ {
		z_i := prover.Group.Mul(challenge, prover.secrets[i])
		z_i = prover.Group.Add(z_i, prover.randomValues[i])
		proofData = append(proofData, z_i)
	}
	return proofData
}

type SchnorrVerifier struct {
	Group           *groups.SchnorrGroup
	bases           []*big.Int
	proofRandomData *big.Int
	y               *big.Int
	challenge       *big.Int
}

func NewSchnorrVerifier(group *groups.SchnorrGroup) *SchnorrVerifier {
	return &SchnorrVerifier{
		Group: group,
	}
}

// TODO: SetProofRandomData name is not ok - it is not only setting
// proofRandomData, but also bases and y.
// It might be split (a, b for example set in SchnorrVerifier constructor).
func (verifier *SchnorrVerifier) SetProofRandomData(proofRandomData *big.Int, bases []*big.Int,
	y *big.Int) {
	verifier.proofRandomData = proofRandomData
	verifier.bases = bases
	verifier.y = y
}

func (verifier *SchnorrVerifier) GetChallenge() *big.Int {
	challenge := common.GetRandomInt(verifier.Group.Q)
	verifier.challenge = challenge
	return challenge
}

func (verifier *SchnorrVerifier) Verify(proofData []*big.Int) bool {
	// check:
	// g_1^z_1 * ... * g_k^z_k = (g_1^x_1 * ... * g_k^x_k)^challenge * (g_1^r_1 * ... * g_k^r_k)
	left := big.NewInt(1)
	for i := 0; i < len(verifier.bases); i++ {
		t := verifier.Group.Exp(verifier.bases[i], proofData[i])
		left = verifier.Group.Mul(left, t)
	}

	right := verifier.Group.Exp(verifier.y, verifier.challenge)
	right = verifier.Group.Mul(right, verifier.proofRandomData)

	return left.Cmp(right) == 0
}
