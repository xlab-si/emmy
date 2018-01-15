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

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
)

// DFCommitmentMultiplicationProver proves for given commitments
// c1 = g^x1 * h^r1, c2 = g^x2 * h^r2, c3 = g^x3 * h^r3 that x3 = x1 * x2.
// Proof consists of three parallel proofs:
// (1) proof that we can open c1
// (2) proof that we can open c2
// (3) proof that we can open c3, where c3 is seen as
// c3 = G^x3 * H^r3 = G^(x1*x2) * H^r1*x2 * H^(r3 - r1*x2) = c1^x2 * H^(r3 - r1*x2),
// thus a new "G" is c1, "x" is x2, and "r3" is r3 - r1*x2.
type DFCommitmentMultiplicationProver struct {
	committer1         *commitments.DamgardFujisakiCommitter
	committer2         *commitments.DamgardFujisakiCommitter
	committer3         *commitments.DamgardFujisakiCommitter
	challengeSpaceSize int
	y1                 *big.Int
	s1                 *big.Int
	y                  *big.Int
	s2                 *big.Int
	s3                 *big.Int
}

func NewDFCommitmentMultiplicationProver(committer1, committer2,
	committer3 *commitments.DamgardFujisakiCommitter,
	challengeSpaceSize int) *DFCommitmentMultiplicationProver {
	return &DFCommitmentMultiplicationProver{
		committer1:         committer1,
		committer2:         committer2,
		committer3:         committer3,
		challengeSpaceSize: challengeSpaceSize,
	}
}

func (prover *DFCommitmentMultiplicationProver) GetProofRandomData() (*big.Int, *big.Int, *big.Int) {
	nLen := prover.committer1.QRSpecialRSA.N.BitLen()
	b1 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(nLen+prover.challengeSpaceSize)), nil)
	b1.Mul(b1, prover.committer1.T)
	b2 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(
		prover.committer1.B+2*nLen+prover.challengeSpaceSize)), nil)

	// y1 and y from [0, T * 2^(NLength + ChallengeSpaceSize))
	// s1, s2, s3 from [0, 2^(B + 2*NLength + ChallengeSpaceSize))

	y1 := common.GetRandomInt(b1)
	y := common.GetRandomInt(b1)
	prover.y1 = y1
	prover.y = y

	s1 := common.GetRandomInt(b2)
	s2 := common.GetRandomInt(b2)
	s3 := common.GetRandomInt(b2)
	prover.s1 = s1
	prover.s2 = s2
	prover.s3 = s3

	// d1 = G^y1 * H^s1
	// d2 = G^y * H^s2
	// d3 = c1^y * H^s3
	d1 := prover.committer1.ComputeCommit(y1, s1) // ComputeCommit can be called on any of the committers
	d2 := prover.committer1.ComputeCommit(y, s2)
	a1, r1 := prover.committer1.GetDecommitMsg()
	c1 := prover.committer1.ComputeCommit(a1, r1)

	l := prover.committer1.QRSpecialRSA.Exp(c1, y)
	r := prover.committer1.QRSpecialRSA.Exp(prover.committer1.H, s3)
	d3 := prover.committer1.QRSpecialRSA.Mul(l, r)
	return d1, d2, d3
}

func (prover *DFCommitmentMultiplicationProver) GetProofData(challenge *big.Int) (*big.Int, *big.Int,
	*big.Int, *big.Int, *big.Int) {
	// u1 = y1 + challenge*a1 (in Z, not modulo)
	// u = y + challenge*a2 (in Z, not modulo)
	// v1 = s1 + challenge*r1 (in Z, not modulo)
	// v2 = s2 + challenge*r2 (in Z, not modulo)
	// v3 = s3 + challenge*(r3 - a2 * r1) (in Z, not modulo)
	a1, r1 := prover.committer1.GetDecommitMsg()
	a2, r2 := prover.committer2.GetDecommitMsg()
	_, r3 := prover.committer3.GetDecommitMsg()

	u1 := new(big.Int).Mul(challenge, a1)
	u1.Add(u1, prover.y1)

	u := new(big.Int).Mul(challenge, a2)
	u.Add(u, prover.y)

	v1 := new(big.Int).Mul(challenge, r1)
	v1.Add(v1, prover.s1)

	v2 := new(big.Int).Mul(challenge, r2)
	v2.Add(v2, prover.s2)

	r := new(big.Int).Mul(a2, r1)
	r.Sub(r3, r)

	v3 := new(big.Int).Mul(challenge, r)
	v3.Add(v3, prover.s3)

	return u1, u, v1, v2, v3
}

type DFCommitmentMultiplicationVerifier struct {
	receiver1          *commitments.DamgardFujisakiReceiver
	receiver2          *commitments.DamgardFujisakiReceiver
	receiver3          *commitments.DamgardFujisakiReceiver
	challengeSpaceSize int
	challenge          *big.Int
	d1                 *big.Int
	d2                 *big.Int
	d3                 *big.Int
}

func NewDFCommitmentMultiplicationVerifier(receiver1, receiver2,
	receiver3 *commitments.DamgardFujisakiReceiver,
	challengeSpaceSize int) *DFCommitmentMultiplicationVerifier {
	return &DFCommitmentMultiplicationVerifier{
		receiver1:          receiver1,
		receiver2:          receiver2,
		receiver3:          receiver3,
		challengeSpaceSize: challengeSpaceSize,
	}
}

func (verifier *DFCommitmentMultiplicationVerifier) SetProofRandomData(d1, d2, d3 *big.Int) {
	verifier.d1 = d1
	verifier.d2 = d2
	verifier.d3 = d3
}

func (verifier *DFCommitmentMultiplicationVerifier) GetChallenge() *big.Int {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(verifier.challengeSpaceSize)), nil)
	challenge := common.GetRandomInt(b)
	verifier.challenge = challenge
	return challenge
}

func (verifier *DFCommitmentMultiplicationVerifier) Verify(u1, u, v1, v2, v3 *big.Int) bool {
	// verify:
	// G^u1 * H^v1 = d1 * c1^challenge
	// G^u * H^v2 = d2 * c2^challenge
	// c1^u * H^v3 = d3 * c3^challenge
	left1 := verifier.receiver1.ComputeCommit(u1, v1)
	right1 := verifier.receiver1.QRSpecialRSA.Exp(verifier.receiver1.Commitment, verifier.challenge)
	right1 = verifier.receiver1.QRSpecialRSA.Mul(verifier.d1, right1)

	left2 := verifier.receiver1.ComputeCommit(u, v2)
	right2 := verifier.receiver1.QRSpecialRSA.Exp(verifier.receiver2.Commitment, verifier.challenge)
	right2 = verifier.receiver1.QRSpecialRSA.Mul(verifier.d2, right2)

	tmp1 := verifier.receiver3.QRSpecialRSA.Exp(verifier.receiver1.Commitment, u) // c1^u

	// TODO
	v3Abs := new(big.Int).Abs(v3)
	var tmp2 *big.Int // H^v3
	if v3Abs.Cmp(v3) == 0 {
		tmp2 = verifier.receiver3.QRSpecialRSA.Exp(verifier.receiver3.H, v3)
	} else {
		tmp2 = verifier.receiver3.QRSpecialRSA.Exp(verifier.receiver3.H, v3Abs)
		tmp2 = verifier.receiver3.QRSpecialRSA.Inv(tmp2)
	}

	left3 := verifier.receiver3.QRSpecialRSA.Mul(tmp1, tmp2)
	right3 := verifier.receiver1.QRSpecialRSA.Exp(verifier.receiver3.Commitment, verifier.challenge)
	right3 = verifier.receiver1.QRSpecialRSA.Mul(verifier.d3, right3)
	return left1.Cmp(right1) == 0 && left2.Cmp(right2) == 0 && left3.Cmp(right3) == 0
}
