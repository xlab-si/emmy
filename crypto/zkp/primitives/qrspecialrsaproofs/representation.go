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

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

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
		group:   qrSpecialRSA,
		secParam:     secParam,
		secrets: secrets,
		bases:   bases,
		y:       y,
	}
}

func (p *RepresentationProver) GetProofRandomData() *big.Int {
	nLen := p.group.N.BitLen()
	exp := big.NewInt(int64(nLen + p.secParam))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	// t = g_1^r_1 * ... * g_k^r_k where g_i are bases and r_i are random values
	t := big.NewInt(1)
	var randomVals = make([]*big.Int, len(p.bases))
	for i, _ := range randomVals {
		r := common.GetRandomInt(b)
		randomVals[i] = r
		f := p.group.Exp(p.bases[i], r)
		t = p.group.Mul(t, f)
	}
	p.randomVals = randomVals
	return t
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
