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

package qrspecialrsaproofs

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

// TestQRSpecialRSA demonstrates how to prove that for a given y you know secrets x_1,...,x_k
// such that y = g_1^x_1 * ... * g_k^x_k where g_i are given generators (bases) of QRSpecialRSA.
func TestQRSpecialRSA(t *testing.T) {
	group, err := groups.NewQRSpecialRSA(128)
	if err != nil {
		t.Errorf("error when creating QRSpecialRSA group: %v", err)
	}

	bases := make([]*big.Int, 3)
	for i := 0; i < len(bases); i++ {
		h, err := group.GetRandomGenerator()
		if err != nil {
			t.Errorf("error when generating QRSpecialRSA generator: %v", err)
		}
		bases[i] = h
	}

	secrets := make([]*big.Int, 3)
	for i := 0; i < 3; i++ {
		secrets[i] = common.GetRandomInt(group.Order)
	}

	// y = g_1^x_1 * ... * g_k^x_k where g_i are bases and x_i are secrets
	y := big.NewInt(1)
	for i := 0; i < 3; i++ {
		f := group.Exp(bases[i], secrets[i])
		y = group.Mul(y, f)
	}

	prover := NewRepresentationProver(group, 80, secrets, bases, y)
	verifier := NewRepresentationVerifier(group, 80)

	proofRandomData := prover.GetProofRandomData(false)
	verifier.SetProofRandomData(proofRandomData, bases, y)

	challenge := verifier.GetChallenge()
	proofData := prover.GetProofData(challenge)
	proved := verifier.Verify(proofData)

	assert.Equal(t, true, proved, "Representation proof failed.")
}
