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

	"fmt"

	"github.com/xlab-si/emmy/crypto/commitments"
)

// DFCommitmentRangeProver proves that the commitment hides a number x such that a <= x <= b.
// Given c, prove that c = g^x * h^r (mod n) where a <= x <= b.
type DFCommitmentRangeProver struct {
	prover1 *DFCommitmentPositiveProver
	prover2 *DFCommitmentPositiveProver
}

func NewDFCommitmentRangeProver(committer *commitments.DamgardFujisakiCommitter,
	x, a, b *big.Int, challengeSpaceSize int) (*DFCommitmentRangeProver, error) {

	// We will prove that b-x >= 0 and x-a >= 0.
	bx := new(big.Int).Sub(b, x)
	xa := new(big.Int).Sub(x, a)
	_, r := committer.GetDecommitMsg()

	rNeg := new(big.Int).Neg(r) // we act as commitment is: g^b / (g^x * h^r) = g^(b-x) * h^(-r)
	prover1, err := NewDFCommitmentPositiveProver(committer, bx, rNeg,
		challengeSpaceSize)
	if err != nil {
		return nil, fmt.Errorf("error in instantiating DFCommitmentPositiveProver")
	}
	prover2, err := NewDFCommitmentPositiveProver(committer, xa, r,
		challengeSpaceSize)
	if err != nil {
		return nil, fmt.Errorf("error in instantiating DFCommitmentPositiveProver")
	}

	return &DFCommitmentRangeProver{
		prover1: prover1,
		prover2: prover2,
	}, nil
}

func (p *DFCommitmentRangeProver) GetProofRandomData() []*big.Int {
	proofRandomData1 := p.prover1.GetProofRandomData()
	proofRandomData2 := p.prover2.GetProofRandomData()
	return append(proofRandomData1, proofRandomData2...)
}

func (p *DFCommitmentRangeProver) GetProofData(challenges []*big.Int) ([]*big.Int, error) {
	if len(challenges) != 8 {
		return nil, fmt.Errorf("length of challenges is not correct")
	}
	proofData1 := p.prover1.GetProofData(challenges[0:4])
	proofData2 := p.prover2.GetProofData(challenges[4:8])
	return append(proofData1, proofData2...), nil
}

// GetVerifierInitializationData returns data that are needed by DFCommitmentRangeVerifier
// and are known only after the initialization of DFCommitmentRangeProver.
func (p *DFCommitmentRangeProver) GetVerifierInitializationData() ([]*big.Int, []*big.Int, []*big.Int,
	[]*big.Int) {
	return p.prover1.SmallCommitments, p.prover1.BigCommitments, p.prover2.SmallCommitments,
		p.prover2.BigCommitments
}

type DFCommitmentRangeVerifier struct {
	verifier1       *DFCommitmentPositiveVerifier
	verifier2       *DFCommitmentPositiveVerifier
	proofRandomData []*big.Int
}

func NewDFCommitmentRangeVerifier(receiver *commitments.DamgardFujisakiReceiver, a, b *big.Int,
	smallCommitments1, bigCommitments1, smallCommitments2, bigCommitments2 []*big.Int,
	challengeSpaceSize int) (*DFCommitmentRangeVerifier, error) {

	// receiverCommitment1 = g^b / c
	receiverCommitment1 := receiver.QRSpecialRSA.Exp(receiver.G, b)
	cInv := receiver.QRSpecialRSA.Inv(receiver.Commitment)
	receiverCommitment1 = receiver.QRSpecialRSA.Mul(receiverCommitment1, cInv)

	verifier1, err := NewDFCommitmentPositiveVerifier(receiver, receiverCommitment1, smallCommitments1,
		bigCommitments1, challengeSpaceSize)
	if err != nil {
		return nil, fmt.Errorf("error in instantiating DFCommitmentPositiveVerifier")
	}

	// receiverCommitment2 = c / g^a
	gToa := receiver.QRSpecialRSA.Exp(receiver.G, a)
	gToaInv := receiver.QRSpecialRSA.Inv(gToa)
	receiverCommitment2 := receiver.QRSpecialRSA.Mul(receiver.Commitment, gToaInv)

	verifier2, err := NewDFCommitmentPositiveVerifier(receiver, receiverCommitment2, smallCommitments2,
		bigCommitments2, challengeSpaceSize)
	if err != nil {
		return nil, fmt.Errorf("error in instantiating DFCommitmentPositiveVerifier")
	}

	return &DFCommitmentRangeVerifier{
		verifier1: verifier1,
		verifier2: verifier2,
	}, nil
}

func (v *DFCommitmentRangeVerifier) GetChallenges() []*big.Int {
	challenges1 := v.verifier1.GetChallenges()
	challenges2 := v.verifier2.GetChallenges()
	return append(challenges1, challenges2...)
}

func (v *DFCommitmentRangeVerifier) SetProofRandomData(proofRandomData []*big.Int) error {
	if len(proofRandomData) != 16 {
		return fmt.Errorf("length of proofRandomData is not correct")
	}
	v.verifier1.SetProofRandomData(proofRandomData[0:8])
	v.verifier2.SetProofRandomData(proofRandomData[8:16])
	return nil
}

func (v *DFCommitmentRangeVerifier) Verify(proofData []*big.Int) (bool, error) {
	if len(proofData) != 24 {
		return false, fmt.Errorf("length of proofData is not correct")
	}
	return v.verifier1.Verify(proofData[0:12]) && v.verifier2.Verify(proofData[12:24]), nil
}
