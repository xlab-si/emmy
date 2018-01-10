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

package representationproofs

import (
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

// ProveKnowledgeOfRepresentation demonstrates how the prover proves that it knows (x_1,...,x_k)
// such that y = g_1^x_1 * ... * g_k^x_k where g_i are given generators of cyclic group G.
// Note that Schnorr is a special case of RepresentationProver where only one base is used.
func ProveKnowledgeOfRepresentation() bool {
	group, err := groups.NewSchnorrGroup(256)
	if err != nil {
		fmt.Printf("Error when generating SchnorrGroup: %v", err)
		return false
	}

	var bases [3]*big.Int
	for i := 0; i < len(bases); i++ {
		r := common.GetRandomInt(group.Q)
		base := group.Exp(group.G, r)
		bases[i] = base
	}

	var secrets [3]*big.Int
	for i := 0; i < 3; i++ {
		secret := common.GetRandomInt(group.Q)
		secrets[i] = secret
	}

	// y = g_1^x_1 * ... * g_k^x_k where g_i are bases and x_i are secrets
	y := big.NewInt(1)
	for i := 0; i < 3; i++ {
		f := group.Exp(bases[i], secrets[i])
		y = group.Mul(y, f)
	}

	prover, err := NewRepresentationProver(group, secrets[:], bases[:], y)
	if err != nil {
		fmt.Printf("Error when instantiating RepresentationProver")
		return false
	}
	verifier := NewRepresentationVerifier(group, bases[:], y)

	proofRandomData := prover.GetProofRandomData()
	verifier.SetProofRandomData(proofRandomData)

	challenge := verifier.GetChallenge()
	proofData := prover.GetProofData(challenge)
	verified := verifier.Verify(proofData)
	return verified
}

type RepresentationProver struct {
	Group        *groups.SchnorrGroup
	secrets      []*big.Int
	bases        []*big.Int
	randomValues []*big.Int
	y            *big.Int
}

func NewRepresentationProver(group *groups.SchnorrGroup, secrets,
	bases []*big.Int, y *big.Int) (*RepresentationProver, error) {
	if len(secrets) != len(bases) {
		return nil, fmt.Errorf("number of secrets and representation bases shoud be the same")
	}

	return &RepresentationProver{
		Group:   group,
		secrets: secrets,
		bases:   bases,
		y:       y,
	}, nil
}

func (prover *RepresentationProver) GetProofRandomData() *big.Int {
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

func (prover *RepresentationProver) GetProofData(challenge *big.Int) []*big.Int {
	// z_i = r_i + challenge * secrets[i]
	var proofData []*big.Int
	for i := 0; i < len(prover.bases); i++ {
		z_i := prover.Group.Mul(challenge, prover.secrets[i])
		z_i = prover.Group.Add(z_i, prover.randomValues[i])
		proofData = append(proofData, z_i)
	}
	return proofData
}

type RepresentationVerifier struct {
	Group           *groups.SchnorrGroup
	bases           []*big.Int
	proofRandomData *big.Int
	y               *big.Int
	challenge       *big.Int
}

func NewRepresentationVerifier(group *groups.SchnorrGroup, bases []*big.Int,
	y *big.Int) *RepresentationVerifier {
	return &RepresentationVerifier{
		Group: group,
		bases: bases,
		y:     y,
	}
}

func (verifier *RepresentationVerifier) SetProofRandomData(proofRandomData *big.Int) {
	verifier.proofRandomData = proofRandomData
}

func (verifier *RepresentationVerifier) GetChallenge() *big.Int {
	challenge := common.GetRandomInt(verifier.Group.Q)
	verifier.challenge = challenge
	return challenge
}

func (verifier *RepresentationVerifier) Verify(proofData []*big.Int) bool {
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
