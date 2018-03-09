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
	"github.com/xlab-si/emmy/crypto/common"
)

// DFCommitmentPositiveProver proves that the commitment hides the positive number. Given c,
// prove that c = g^x * h^r (mod n) where x >= 0.
type DFCommitmentPositiveProver struct {
	squareProvers []*DFCommitmentSquareProver
}

func NewDFCommitmentPositiveProver(committer *commitments.DamgardFujisakiCommitter,
	x, r *big.Int, challengeSpaceSize int) (*DFCommitmentPositiveProver, []*big.Int, []*big.Int, error) {

	// x can be written (if positive) as x = x0^2 + x1^2 + x2^2 + x3^2.
	// We create committers which hold c0 = g^(x0^2) * h^r0, c1 = g^(x1^2) * h^r1,
	// c2 = g^(x2^2) * h^r2, c3 = g^(x3^2) * h^r3 and where r = r0 + r1 + r2 + r3.
	// We then prove that c0, c1, c2, c3 contains squares and verifier checks that c = c0*c1*c2*c3.

	roots, err := common.LipmaaDecomposition(x)
	if err != nil {
		return nil, []*big.Int(nil), []*big.Int(nil),
			fmt.Errorf("error when doing Limpaa decomposition")
	}
	numOfRoots := len(roots)

	// find r0, r1, r2, r3 such that r0 + r1 + r2 + r3 = r

	rIsNegative := false
	rAbs := new(big.Int).Abs(r)
	if rAbs.Cmp(r) != 0 {
		rIsNegative = true
	}

	boundary := new(big.Int)
	boundary.Set(rAbs)

	var rs []*big.Int
	for i := 0; i < numOfRoots; i++ {
		currR := common.GetRandomInt(boundary)
		if i < numOfRoots-1 {
			rs = append(rs, currR)
			boundary.Sub(boundary, currR)
		} else {
			rs = append(rs, boundary)
		}
	}

	if rIsNegative {
		for i := 0; i < numOfRoots; i++ {
			rs[i].Neg(rs[i])
		}
	}

	var committers []*commitments.DamgardFujisakiCommitter
	var commitmentsToSquares []*big.Int
	for i := 0; i < numOfRoots; i++ {
		committer := commitments.NewDamgardFujisakiCommitter(committer.QRSpecialRSA.N,
			committer.H, committer.G, committer.T, committer.K)
		square := new(big.Int).Mul(roots[i], roots[i])
		commitment, err := committer.GetCommitMsgWithGivenR(square, rs[i])
		commitmentsToSquares = append(commitmentsToSquares, commitment)
		if err != nil {
			return nil, []*big.Int(nil), []*big.Int(nil),
				fmt.Errorf("error when creating commit msg")
		}
		committers = append(committers, committer)
	}

	var bases []*big.Int
	var squareProvers []*DFCommitmentSquareProver
	for i := 0; i < numOfRoots; i++ {
		prover, c1, err := NewDFCommitmentSquareProver(committers[i], roots[i], challengeSpaceSize)
		if err != nil {
			return nil, []*big.Int(nil), []*big.Int(nil),
				fmt.Errorf("Error in instantiating DFCommitmentSquareProver")
		}
		bases = append(bases, c1)
		squareProvers = append(squareProvers, prover)
	}

	return &DFCommitmentPositiveProver{
		squareProvers: squareProvers,
	}, bases, commitmentsToSquares, nil
}

func (prover *DFCommitmentPositiveProver) GetProofRandomData() []*big.Int {
	var proofRandomData []*big.Int
	for i := 0; i < len(prover.squareProvers); i++ {
		proofRandomData1, proofRandomData2 := prover.squareProvers[i].GetProofRandomData()
		proofRandomData = append(proofRandomData, proofRandomData1)
		proofRandomData = append(proofRandomData, proofRandomData2)
	}
	return proofRandomData
}

func (prover *DFCommitmentPositiveProver) GetProofData(challenges []*big.Int) []*big.Int {
	numOfRoots := len(prover.squareProvers)
	var proofData []*big.Int
	for i := 0; i < numOfRoots; i++ {
		s1, s21, s22 := prover.squareProvers[i].GetProofData(challenges[i])
		proofData = append(proofData, s1)
		proofData = append(proofData, s21)
		proofData = append(proofData, s22)
	}
	return proofData
}

type DFCommitmentPositiveVerifier struct {
	squareVerifiers []*DFCommitmentSquareVerifier
	proofRandomData []*big.Int
}

func NewDFCommitmentPositiveVerifier(receiver *commitments.DamgardFujisakiReceiver,
	receiverCommitment *big.Int, bases []*big.Int, commitmentsToSquares []*big.Int,
	challengeSpaceSize int) (*DFCommitmentPositiveVerifier, error) {

	numOfRoots := len(bases)
	// check: c = c0*c1*c2*c3
	check := big.NewInt(1)
	for i := 0; i < numOfRoots; i++ {
		check = receiver.QRSpecialRSA.Mul(check, commitmentsToSquares[i])
	}
	if receiverCommitment.Cmp(check) != 0 {
		return nil, fmt.Errorf("squareProvers are not properly instantiated")
	}

	var receivers []*commitments.DamgardFujisakiReceiver
	for i := 0; i < numOfRoots; i++ {
		receiver, err := commitments.NewDamgardFujisakiReceiverFromParams(receiver.QRSpecialRSA,
			receiver.H, receiver.G, receiver.K)
		if err != nil {
			return nil, fmt.Errorf("error when calling NewDamgardFujisakiReceiverFromParams")
		}
		receiver.SetCommitment(commitmentsToSquares[i])
		receivers = append(receivers, receiver)
	}

	var squareVerifiers []*DFCommitmentSquareVerifier
	for i := 0; i < numOfRoots; i++ {
		verifier, err := NewDFCommitmentSquareVerifier(receivers[i], bases[i], challengeSpaceSize)
		if err != nil {
			return nil, fmt.Errorf("error when creating DFCommitmentSquareVerifier")
		}
		squareVerifiers = append(squareVerifiers, verifier)
	}

	return &DFCommitmentPositiveVerifier{
		squareVerifiers: squareVerifiers,
	}, nil
}

func (verifier *DFCommitmentPositiveVerifier) GetChallenges() []*big.Int {
	numOfRoots := len(verifier.squareVerifiers)
	var challenges []*big.Int
	for i := 0; i < numOfRoots; i++ {
		challenge := verifier.squareVerifiers[i].GetChallenge()
		challenges = append(challenges, challenge)
	}
	return challenges
}

func (verifier *DFCommitmentPositiveVerifier) SetProofRandomData(proofRandomData []*big.Int) {
	numOfRoots := len(verifier.squareVerifiers)
	for i := 0; i < numOfRoots; i++ {
		verifier.squareVerifiers[i].SetProofRandomData(proofRandomData[2*i], proofRandomData[2*i+1])
	}
}

func (verifier *DFCommitmentPositiveVerifier) Verify(proofData []*big.Int) bool {
	numOfRoots := len(verifier.squareVerifiers)
	verified := true
	for i := 0; i < numOfRoots; i++ {
		ver := verifier.squareVerifiers[i].Verify(proofData[3*i], proofData[3*i+1],
			proofData[3*i+2])
		verified = verified && ver
	}
	return verified
}
