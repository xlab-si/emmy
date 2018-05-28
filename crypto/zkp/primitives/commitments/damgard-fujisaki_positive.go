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
	squareProvers    []*DFCommitmentSquareProver
	smallCommitments []*big.Int
	bigCommitments   []*big.Int
}

func NewDFCommitmentPositiveProver(committer *commitments.DamgardFujisakiCommitter,
	x, r *big.Int, challengeSpaceSize int) (*DFCommitmentPositiveProver, error) {

	// x can be written (if positive) as x = x0^2 + x1^2 + x2^2 + x3^2.
	// We create committers which hold c0 = g^(x0^2) * h^r0, c1 = g^(x1^2) * h^r1,
	// c2 = g^(x2^2) * h^r2, c3 = g^(x3^2) * h^r3 and where r = r0 + r1 + r2 + r3.
	// We then prove that c0, c1, c2, c3 contains squares and verifier checks that c = c0*c1*c2*c3.

	roots, err := common.LipmaaDecomposition(x)
	if err != nil {
		return nil, fmt.Errorf("error when doing Lipmaa decomposition")
	}
	nRoots := len(roots)

	// find r0, r1, r2, r3 such that r0 + r1 + r2 + r3 = r
	rs := getCommitRandoms(r, nRoots)

	committers := make([]*commitments.DamgardFujisakiCommitter, nRoots)
	bigCommitments := make([]*big.Int, nRoots)
	for i, rand := range rs {
		committer := commitments.NewDamgardFujisakiCommitter(committer.QRSpecialRSA.N,
			committer.H, committer.G, committer.T, committer.K)
		square := new(big.Int).Mul(roots[i], roots[i])
		commitment, err := committer.GetCommitMsgWithGivenR(square, rand)
		bigCommitments[i] = commitment
		if err != nil {
			return nil, fmt.Errorf("error when creating commit msg")
		}
		committers[i] = committer
	}

	smallCommitments := make([]*big.Int, nRoots)
	squareProvers := make([]*DFCommitmentSquareProver, nRoots)
	for i, root := range roots {
		prover, err := NewDFCommitmentSquareProver(committers[i], root, challengeSpaceSize)
		if err != nil {
			return nil, fmt.Errorf("error in instantiating DFCommitmentSquareProver")
		}
		smallCommitments[i] = prover.SmallCommitment
		squareProvers[i] = prover
	}

	return &DFCommitmentPositiveProver{
		squareProvers:    squareProvers,
		smallCommitments: smallCommitments,
		bigCommitments:   bigCommitments,
	}, nil
}

// getCommitRandoms returns slice containing r_i for 0 <= i < nRoots such that
// r = r_0 + ... + r_(nRoots-1).
func getCommitRandoms(r *big.Int, nRoots int) []*big.Int {
	rAbs := new(big.Int).Abs(r) // r can be negative, see range proof
	boundary := new(big.Int).Set(rAbs)

	rs := make([]*big.Int, nRoots)
	for i, _ := range rs {
		r := common.GetRandomInt(boundary)
		if i < nRoots-1 {
			rs[i] = r
			boundary.Sub(boundary, r)
		} else {
			rs[i] = boundary
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
	for i, squareProver := range p.squareProvers {
		proofRandomData1, proofRandomData2 := squareProver.GetProofRandomData()
		proofRandomData[2*i] = proofRandomData1
		proofRandomData[2*i+1] = proofRandomData2
	}
	return proofRandomData
}

func (p *DFCommitmentPositiveProver) GetProofData(challenges []*big.Int) []*big.Int {
	proofData := make([]*big.Int, len(p.squareProvers)*3)
	for i, squareProver := range p.squareProvers {
		s1, s21, s22 := squareProver.GetProofData(challenges[i])
		proofData[3*i] = s1
		proofData[3*i+1] = s21
		proofData[3*i+2] = s22
	}
	return proofData
}

// GetVerifierInitializationData returns data that are needed by DFCommitmentPositiveVerifier
// and are known only after the initialization of DFCommitmentPositiveProver.
func (p *DFCommitmentPositiveProver) GetVerifierInitializationData() ([]*big.Int, []*big.Int) {
	return p.smallCommitments, p.bigCommitments
}

type DFCommitmentPositiveVerifier struct {
	squareVerifiers []*DFCommitmentSquareVerifier
	proofRandomData []*big.Int
}

func NewDFCommitmentPositiveVerifier(receiver *commitments.DamgardFujisakiReceiver,
	receiverCommitment *big.Int, smallCommitments, bigCommitments []*big.Int,
	challengeSpaceSize int) (*DFCommitmentPositiveVerifier, error) {

	nRoots := len(smallCommitments)
	// check: c = c0*c1*c2*c3
	check := big.NewInt(1)
	for i := 0; i < nRoots; i++ {
		check = receiver.QRSpecialRSA.Mul(check, bigCommitments[i])
	}
	if receiverCommitment.Cmp(check) != 0 {
		return nil, fmt.Errorf("squareProvers are not properly instantiated")
	}

	receivers := make([]*commitments.DamgardFujisakiReceiver, nRoots)
	for i, comm := range bigCommitments {
		receiver, err := commitments.NewDamgardFujisakiReceiverFromParams(
			receiver.QRSpecialRSA.GetSpecialRSAPrimes(),
			receiver.H, receiver.G, receiver.K)
		if err != nil {
			return nil, fmt.Errorf("error when calling NewDamgardFujisakiReceiverFromParams")
		}
		receiver.SetCommitment(comm)
		receivers[i] = receiver
	}

	squareVerifiers := make([]*DFCommitmentSquareVerifier, nRoots)
	for i, receiver := range receivers {
		verifier, err := NewDFCommitmentSquareVerifier(receiver, smallCommitments[i], challengeSpaceSize)
		if err != nil {
			return nil, fmt.Errorf("error when creating DFCommitmentSquareVerifier")
		}
		squareVerifiers[i] = verifier
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

func (v *DFCommitmentPositiveVerifier) SetProofRandomData(proofRandomData []*big.Int) error {
	if len(proofRandomData) != 8 {
		return fmt.Errorf("the length of proofRandomData is not correct")
	}
	for i, verifier := range v.squareVerifiers {
		verifier.SetProofRandomData(proofRandomData[2*i], proofRandomData[2*i+1])
	}
	return nil
}

func (v *DFCommitmentPositiveVerifier) Verify(proofData []*big.Int) bool {
	if len(proofData) != 12 {
		return false
	}
	verified := true
	for i, verifier := range v.squareVerifiers {
		verified = verified && verifier.Verify(proofData[3*i], proofData[3*i+1], proofData[3*i+2])
	}
	return verified
}
