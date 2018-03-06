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

// DFCommitmentSquareProver proves that the commitment hides the square. Given c,
// prove that c = g^(x^2) * h^r (mod n).
type DFCommitmentSquareProver struct {
	*DFCommitmentEqualityProver
}

func NewDFCommitmentSquareProver(committer *commitments.DamgardFujisakiCommitter,
	x *big.Int, challengeSpaceSize int) (*DFCommitmentSquareProver, *big.Int, error) {

	// Input committer contains c = g^(x^2) * h^r (mod n).
	// We now create two committers - committer1 will contain c1 = g^x * h^r1 (mod n),
	// committer2 will contain the same c as committer, but using a different base c = c1^x * h^r2.
	// Note that c = c1^x * h^r2 = g^(x^2) * h^(r1*x) * h^r2, so we choose r2 = r - r1*x.
	// DFCommitmentSquareProver proves that committer1 and committer2 hide the same value (x) -
	// using DFCommitmentEqualityProver.

	committer1 := commitments.NewDamgardFujisakiCommitter(committer.QRSpecialRSA.N,
		committer.H, committer.G, committer.T, committer.K)
	c1, err := committer1.GetCommitMsg(x)
	if err != nil {
		return nil, nil, fmt.Errorf("error when creating commit msg")
	}

	committer2 := commitments.NewDamgardFujisakiCommitter(committer.QRSpecialRSA.N,
		committer.H, c1, committer.T, committer.K)
	_, r := committer.GetDecommitMsg()
	_, r1 := committer1.GetDecommitMsg()
	r1x := new(big.Int).Mul(r1, x)
	r2 := new(big.Int).Sub(r, r1x)

	// we already know the commitment (it is c), so we ignore the first variable -
	// just need to set the committer2 committedValue and r:
	_, err = committer2.GetCommitMsgWithGivenR(x, r2)
	if err != nil {
		return nil, nil, fmt.Errorf("error when creating commit msg with given r")
	}

	prover := NewDFCommitmentEqualityProver(committer1, committer2, challengeSpaceSize)

	return &DFCommitmentSquareProver{
		prover,
	}, c1, nil
}

type DFCommitmentSquareVerifier struct {
	*DFCommitmentEqualityVerifier
}

func NewDFCommitmentSquareVerifier(receiver *commitments.DamgardFujisakiReceiver,
	c1 *big.Int, challengeSpaceSize int) (*DFCommitmentSquareVerifier, error) {

	receiver1, err := commitments.NewDamgardFujisakiReceiverFromParams(receiver.QRSpecialRSA,
		receiver.H, receiver.G, receiver.K)
	if err != nil {
		return nil, fmt.Errorf("error when calling NewDamgardFujisakiReceiverFromParams")
	}
	receiver1.SetCommitment(c1)

	receiver2, err := commitments.NewDamgardFujisakiReceiverFromParams(receiver.QRSpecialRSA,
		receiver.H, c1, receiver.K)
	if err != nil {
		return nil, fmt.Errorf("error when calling NewDamgardFujisakiReceiverFromParams")
	}
	receiver2.SetCommitment(receiver.Commitment)

	verifier := NewDFCommitmentEqualityVerifier(receiver1, receiver2, challengeSpaceSize)

	return &DFCommitmentSquareVerifier{
		verifier,
	}, nil
}
