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
			fmt.Errorf("error when doing Lipmaa decomposition")
	}
	numOfRoots := len(roots)

	// find r0, r1, r2, r3 such that r0 + r1 + r2 + r3 = r
	rs := getCommitRandoms(r, numOfRoots)

	committers := make([]*commitments.DamgardFujisakiCommitter, numOfRoots)
	commitmentsToSquares := make([]*big.Int, numOfRoots)
	//for i := 0; i < numOfRoots; i++ {
	for index, rand := range rs {
		committer := commitments.NewDamgardFujisakiCommitter(committer.QRSpecialRSA.N,
			committer.H, committer.G, committer.T, committer.K)
		square := new(big.Int).Mul(roots[index], roots[index])
		commitment, err := committer.GetCommitMsgWithGivenR(square, rand)
		commitmentsToSquares[index] = commitment
		if err != nil {
			return nil, []*big.Int(nil), []*big.Int(nil),
				fmt.Errorf("error when creating commit msg")
		}
		committers[index] = committer
	}

	bases := make([]*big.Int, numOfRoots)
	squareProvers := make([]*DFCommitmentSquareProver, numOfRoots)
	for index, root := range roots {
		prover, c1, err := NewDFCommitmentSquareProver(committers[index], root, challengeSpaceSize)
		if err != nil {
			return nil, []*big.Int(nil), []*big.Int(nil),
				fmt.Errorf("error in instantiating DFCommitmentSquareProver")
		}
		bases[index] = c1
		squareProvers[index] = prover
	}

	return &DFCommitmentPositiveProver{
		squareProvers: squareProvers,
	}, bases, commitmentsToSquares, nil
}

// getCommitRandoms returns slice containing r_i for 0 <= i < numOfRoots such that
// r = r_0 + ... + r_(numOfRoots-1).
func getCommitRandoms(r *big.Int, numOfRoots int) []*big.Int {
	rAbs := new(big.Int).Abs(r) // r can be negative, see range proof
	boundary := new(big.Int).Set(rAbs)

	rs := make([]*big.Int, numOfRoots)
	for index, _ := range rs {
		currR := common.GetRandomInt(boundary)
		if index < numOfRoots-1 {
			rs[index] = currR
			boundary.Sub(boundary, currR)
		} else {
			rs[index] = boundary
		}
	}

	if rAbs.Cmp(r) != 0 { // if r is negative
		for _, elem := range rs {
			elem.Neg(elem)
		}
	}
	return rs
}

func (p *DFCommitmentPositiveProver) GetProofRandomData() []*big.Int {
	proofRandomData := make([]*big.Int, len(p.squareProvers)*2)
	for index, squareProver := range p.squareProvers {
		proofRandomData1, proofRandomData2 := squareProver.GetProofRandomData()
		proofRandomData[2*index] = proofRandomData1
		proofRandomData[2*index+1] = proofRandomData2
	}
	return proofRandomData
}

func (p *DFCommitmentPositiveProver) GetProofData(challenges []*big.Int) []*big.Int {
	proofData := make([]*big.Int, len(p.squareProvers)*3)
	for index, squareProver := range p.squareProvers {
		s1, s21, s22 := squareProver.GetProofData(challenges[index])
		proofData[3*index] = s1
		proofData[3*index+1] = s21
		proofData[3*index+2] = s22
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

	receivers := make([]*commitments.DamgardFujisakiReceiver, numOfRoots)
	for index, comm := range commitmentsToSquares {
		receiver, err := commitments.NewDamgardFujisakiReceiverFromParams(receiver.QRSpecialRSA,
			receiver.H, receiver.G, receiver.K)
		if err != nil {
			return nil, fmt.Errorf("error when calling NewDamgardFujisakiReceiverFromParams")
		}
		receiver.SetCommitment(comm)
		receivers[index] = receiver
	}

	squareVerifiers := make([]*DFCommitmentSquareVerifier, numOfRoots)
	for index, receiver := range receivers {
		verifier, err := NewDFCommitmentSquareVerifier(receiver, bases[index], challengeSpaceSize)
		if err != nil {
			return nil, fmt.Errorf("error when creating DFCommitmentSquareVerifier")
		}
		squareVerifiers[index] = verifier
	}

	return &DFCommitmentPositiveVerifier{
		squareVerifiers: squareVerifiers,
	}, nil
}

func (v *DFCommitmentPositiveVerifier) GetChallenges() []*big.Int {
	challenges := make([]*big.Int, len(v.squareVerifiers))
	for i, v := range v.squareVerifiers {
		challenges[i] = v.GetChallenge()
	}
	return challenges
}

func (v *DFCommitmentPositiveVerifier) SetProofRandomData(proofRandomData []*big.Int) {
	for i, verifier := range v.squareVerifiers {
		verifier.SetProofRandomData(proofRandomData[2*i], proofRandomData[2*i+1])
	}
}

func (v *DFCommitmentPositiveVerifier) Verify(proofData []*big.Int) bool {
	verified := true
	for i, verifier := range v.squareVerifiers {
		verified = verified && verifier.Verify(proofData[3*i], proofData[3*i+1], proofData[3*i+2])
	}
	return verified
}
