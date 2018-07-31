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

package cl

import (
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/commitments"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
)

type CredentialRequest struct {
	Nym *big.Int
	KnownAttrs []*big.Int
	CommitmentsOfAttrs []*big.Int
	NymProof                 *dlogproofs.SchnorrProof
	U                        *big.Int
	UProof                   *qrspecialrsaproofs.RepresentationProof
	CommitmentsOfAttrsProofs []*commitmentzkp.DFOpeningProof
	Nonce                    *big.Int
}

func NewCredentialRequest(nym *big.Int, knownAttrs, commitmentsOfAttrs []*big.Int, nymProof *dlogproofs.SchnorrProof,
	U *big.Int, UProof *qrspecialrsaproofs.RepresentationProof,
	commitmentsOfAttrsProofs []*commitmentzkp.DFOpeningProof, nonce *big.Int) *CredentialRequest {
	return &CredentialRequest{
		Nym: nym,
		KnownAttrs: knownAttrs,
		CommitmentsOfAttrs: commitmentsOfAttrs,
		NymProof: nymProof,
		U:        U,
		UProof:   UProof,
		CommitmentsOfAttrsProofs: commitmentsOfAttrsProofs,
		Nonce: nonce,
	}
}

// computeU computes U = S^v1 * R_1^m_1 * ... * R_NumAttrs^m_NumAttrs (mod n) where only hiddenAttrs are used and
// where v1 is random from +-{0,1}^(NLength + SecParam)
func (m *CredentialManager) computeU() (*big.Int, *big.Int) {
	exp := big.NewInt(int64(m.Params.NLength + m.Params.SecParam))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	v1 := common.GetRandomIntAlsoNeg(b)

	group := groups.NewQRSpecialRSAPublic(m.PubKey.N)
	U := group.Exp(m.PubKey.S, v1)

	for i, attr := range m.hiddenAttrs {
		t := group.Exp(m.PubKey.RsHidden[i], attr) // R_i^m_i
		U = group.Mul(U, t)
	}

	return U, v1
}

func (m *CredentialManager) getNymProver() (*dlogproofs.SchnorrProver, error) {
	// use Schnorr with two bases for proving that you know nym opening:
	bases := []*big.Int{
		m.PubKey.PedersenParams.Group.G,
		m.PubKey.PedersenParams.H,
	}
	committer := m.nymCommitter
	val, r := committer.GetDecommitMsg() // val is actually master key
	secrets := []*big.Int{val, r}

	prover, err := dlogproofs.NewSchnorrProver(m.PubKey.PedersenParams.Group, secrets[:], bases[:],
		committer.Commitment)
	if err != nil {
		return nil, fmt.Errorf("error when creating Schnorr prover: %s", err)
	}

	return prover, nil
}

func (m *CredentialManager) getUProver(U *big.Int) *qrspecialrsaproofs.RepresentationProver {
	group := groups.NewQRSpecialRSAPublic(m.PubKey.N)
	// secrets are [attr_1, ..., attr_L, v1]
	secrets := append(m.hiddenAttrs, m.v1)

	// bases are [R_1, ..., R_L, S]
	bases := append(m.PubKey.RsHidden, m.PubKey.S)
	prover := qrspecialrsaproofs.NewRepresentationProver(group, m.Params.SecParam,
		secrets[:], bases[:], U)
	return prover
}

func (m *CredentialManager) getUProofRandomData(prover *qrspecialrsaproofs.RepresentationProver) (*big.Int, error) {
	// boundary for m_tilde
	b_m := m.Params.AttrBitLen + m.Params.SecParam + m.Params.HashBitLen + 1
	// boundary for v1
	b_v1 := m.Params.NLength + 2*m.Params.SecParam + m.Params.HashBitLen

	boundaries := make([]int, len(m.PubKey.RsHidden))
	for i := 0; i < len(m.PubKey.RsHidden); i++ {
		boundaries[i] = b_m
	}
	boundaries = append(boundaries, b_v1)

	UTilde, err := prover.GetProofRandomDataGivenBoundaries(boundaries, true)
	if err != nil {
		return nil, fmt.Errorf("error when generating representation proof random data: %s", err)
	}

	return UTilde, nil
}

// Fiat-Shamir is used to generate a challenge, instead of asking verifier to generate it.
func (m *CredentialManager) getCredReqChallenge(U, nym, nonceOrg *big.Int) *big.Int {
	context := m.PubKey.GetContext()
	l := []*big.Int{context, U, nym, nonceOrg}
	l = append(l, m.CommitmentsOfAttrs...) // TODO: add other values

	return common.Hash(l...)
}

func (m *CredentialManager) getCredReqProvers(U *big.Int) (*dlogproofs.SchnorrProver,
	*qrspecialrsaproofs.RepresentationProver, error) {
	nymProver, err := m.getNymProver()
	if err != nil {
		return nil, nil, fmt.Errorf("error when obtaining nym proof random data: %v", err)
	}
	uProver := m.getUProver(U)

	return nymProver, uProver, nil
}

func (m *CredentialManager) getCommitmentsOfAttrsProof(challenge *big.Int) []*commitmentzkp.DFOpeningProof {
	commitmentsOfAttrsProofs := make([]*commitmentzkp.DFOpeningProof, len(m.commitmentsOfAttrsProvers))
	for i, prover := range m.commitmentsOfAttrsProvers {
		proofRandomData := prover.GetProofRandomData()
		proofData1, proofData2 := prover.GetProofData(challenge)
		commitmentsOfAttrsProofs[i] = commitmentzkp.NewDFOpeningProof(proofRandomData, challenge,
			proofData1, proofData2)
	}

	return commitmentsOfAttrsProofs
}
