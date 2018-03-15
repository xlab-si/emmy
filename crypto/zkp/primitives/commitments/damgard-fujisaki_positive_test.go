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

package commitmentzkp

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
)

// TestProveDamgardFujisakiCommitmentPositive demonstrates how to prove that the commitment
// hides a positive number. Given c, prove that c = g^x * h^r (mod n) where x >= 0.
func TestProveDamgardFujisakiCommitmentPositive(t *testing.T) {
	receiver, err := commitments.NewDamgardFujisakiReceiver(1024, 80)
	if err != nil {
		t.Errorf("error in NewDamgardFujisakiReceiver: %v", err)
	}

	// n^2 is used for T - but any other value can be used as well
	T := new(big.Int).Mul(receiver.QRSpecialRSA.N, receiver.QRSpecialRSA.N)
	committer := commitments.NewDamgardFujisakiCommitter(receiver.QRSpecialRSA.N,
		receiver.H, receiver.G, T, receiver.K)

	x := common.GetRandomInt(committer.QRSpecialRSA.N)
	c, err := committer.GetCommitMsg(x)
	if err != nil {
		t.Errorf("error in computing commit msg: %v", err)
	}
	receiver.SetCommitment(c)
	_, r := committer.GetDecommitMsg()

	challengeSpaceSize := 80
	prover, err := NewDFCommitmentPositiveProver(committer, x, r,
		challengeSpaceSize)
	if err != nil {
		t.Errorf("error in instantiating DFCommitmentPositiveProver: %v", err)
	}

	smallCommitments, bigCommitments := prover.GetVerifierInitializationData()
	verifier, err := NewDFCommitmentPositiveVerifier(receiver, receiver.Commitment,
		smallCommitments, bigCommitments, challengeSpaceSize)
	if err != nil {
		t.Errorf("error in instantiating DFCommitmentPositiveVerifier: %v", err)
	}

	proofRandomData := prover.GetProofRandomData()
	challenges := verifier.GetChallenges()
	err = verifier.SetProofRandomData(proofRandomData)
	if err != nil {
		t.Errorf("error when calling SetProofRandomData: %v", err)
	}
	proofData := prover.GetProofData(challenges)
	proved := verifier.Verify(proofData)
	assert.Equal(t, true, proved, "DamgardFujisaki positive proof failed.")
}
