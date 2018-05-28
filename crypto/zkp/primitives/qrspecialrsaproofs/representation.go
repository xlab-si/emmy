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
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

// TODO: Protocol being proof of knowledge is shown by the existance of knowledge extractor. In Schnorr protocol
// extractor is based on rewinding. In RSA it can be too, but note that when we get y^(c0-c1) = g^(s-s1), we don't
// know the order of group and cannot compute u such that y = g^u. However, due to the strong RSA assumption, we
// know (assume) that (c0-c1) divides (s0-s1). So we have y^(c0-c1) = g^((c0-c1)*u). Now, that doesn't mean
// that y = g^u - it might be y = (b*g)^u such that b^(c0-c1) = 1. It turns out b can be 1 or -1.
// It seems that idemix is solving this by taking random values (used in random proof data) also from negative values -
// is this really needed?

// RepresentationProver is like SchnorrProver but in a QRSpecialRSA group (note that here proof data is
// computed in Z, not modulo as in Schnorr). Also, RepresentationProver with only one base and one secret
// is very similar to the DFCommitmentOpeningProver (RepresentationProver does not have a committer though).
type RepresentationProver struct {
	group      *groups.QRSpecialRSA
	secParam   int // security parameter
	secrets    []*big.Int
	bases      []*big.Int
	randomVals []*big.Int
	y          *big.Int
}

func NewRepresentationProver(qrSpecialRSA *groups.QRSpecialRSA,
	secParam int, secrets, bases []*big.Int, y *big.Int) *RepresentationProver {
	return &RepresentationProver{
		group:    qrSpecialRSA,
		secParam: secParam,
		secrets:  secrets,
		bases:    bases,
		y:        y,
	}
}

// GetProofRandomData returns t = g_1^r_1 * ... * g_k^r_k where g_i are bases and r_i are random values.
// If alsoNeg is true values r_i can be negative as well.
func (p *RepresentationProver) GetProofRandomData(alsoNeg bool) *big.Int {
	nLen := p.group.N.BitLen()
	exp := big.NewInt(int64(nLen + p.secParam))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	t := big.NewInt(1)
	var randomVals = make([]*big.Int, len(p.bases))
	for i, _ := range randomVals {
		var r *big.Int
		if alsoNeg {
			r = common.GetRandomIntAlsoNeg(b)
		} else {
			r = common.GetRandomInt(b)
		}
		randomVals[i] = r
		f := p.group.Exp(p.bases[i], r)
		t = p.group.Mul(t, f)
	}
	p.randomVals = randomVals
	return t
}

// GetProofRandomDataGivenBoundaries returns t = g_1^r_1 * ... * g_k^r_k where g_i are bases and each r_i is a
// random value of boundariesBitLength[i] bit length. If alsoNeg is true values r_i can be negative as well.
func (p *RepresentationProver) GetProofRandomDataGivenBoundaries(boundariesBitLength []int,
	alsoNeg bool) (*big.Int, error) {
	if len(boundariesBitLength) != len(p.bases) {
		return nil, fmt.Errorf("the length of boundariesBitLength should be the same as the number of bases")
	}
	t := big.NewInt(1)
	var randomVals = make([]*big.Int, len(p.bases))
	for i, _ := range randomVals {
		exp := big.NewInt(int64(boundariesBitLength[i]))
		b := new(big.Int).Exp(big.NewInt(2), exp, nil)
		var r *big.Int
		if alsoNeg {
			r = common.GetRandomIntAlsoNeg(b)
		} else {
			r = common.GetRandomInt(b)
		}
		randomVals[i] = r
		f := p.group.Exp(p.bases[i], r)
		t = p.group.Mul(t, f)
	}
	p.randomVals = randomVals
	return t, nil
}

func (p *RepresentationProver) GetProofData(challenge *big.Int) []*big.Int {
	// z_i = r_i + challenge * secrets[i] (in Z, not modulo)
	var proofData = make([]*big.Int, len(p.bases))
	for i, _ := range proofData {
		z_i := new(big.Int).Mul(challenge, p.secrets[i])
		z_i.Add(z_i, p.randomVals[i])
		proofData[i] = z_i
	}
	return proofData
}

// RepresentationProof presents all three messages in sigma protocol - useful when challenge
// is generated by prover via Fiat-Shamir.
type RepresentationProof struct {
	ProofRandomData *big.Int
	Challenge       *big.Int
	ProofData       []*big.Int
}

func NewRepresentationProof(proofRandomData, challenge *big.Int,
	proofData []*big.Int) *RepresentationProof {
	return &RepresentationProof{
		ProofRandomData: proofRandomData,
		Challenge:       challenge,
		ProofData:       proofData,
	}
}

type RepresentationVerifier struct {
	group              *groups.QRSpecialRSA
	challengeSpaceSize int
	challenge          *big.Int
	bases              []*big.Int
	y                  *big.Int
	proofRandomData    *big.Int
}

func NewRepresentationVerifier(qrSpecialRSA *groups.QRSpecialRSA,
	challengeSpaceSize int) *RepresentationVerifier {
	return &RepresentationVerifier{
		group:              qrSpecialRSA,
		challengeSpaceSize: challengeSpaceSize,
	}
}

// TODO: SetProofRandomData name is not ok - it is not only setting
// proofRandomData, but also bases and y.
func (v *RepresentationVerifier) SetProofRandomData(proofRandomData *big.Int, bases []*big.Int,
	y *big.Int) {
	v.proofRandomData = proofRandomData
	v.bases = bases
	v.y = y
}

func (v *RepresentationVerifier) GetChallenge() *big.Int {
	exp := big.NewInt(int64(v.challengeSpaceSize))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	challenge := common.GetRandomInt(b)
	v.challenge = challenge
	return challenge
}

// SetChallenge is used when Fiat-Shamir is used - when challenge is generated using hash by the prover.
func (v *RepresentationVerifier) SetChallenge(challenge *big.Int) {
	v.challenge = challenge
}

func (v *RepresentationVerifier) Verify(proofData []*big.Int) bool {
	// check:
	// g_1^z_1 * ... * g_k^z_k = (g_1^x_1 * ... * g_k^x_k)^challenge * (g_1^r_1 * ... * g_k^r_k)
	left := big.NewInt(1)
	for i := 0; i < len(v.bases); i++ {
		t := v.group.Exp(v.bases[i], proofData[i])
		left = v.group.Mul(left, t)
	}

	right := v.group.Exp(v.y, v.challenge)
	right = v.group.Mul(right, v.proofRandomData)

	return left.Cmp(right) == 0
}
