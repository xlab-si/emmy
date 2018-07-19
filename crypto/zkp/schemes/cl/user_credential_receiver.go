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

type UserCredentialReceiver struct {
	CredentialManager *CredentialManager
	U                 *big.Int
	nymProver         *dlogproofs.SchnorrProver // for proving that nym is of the proper form
	// TODO: not sure what would be the most appropriate name for UProver and UTilde
	UProver                   *qrspecialrsaproofs.RepresentationProver // for proving that U is of the proper form
	nymTilde                  *big.Int                                 // proof random data for nym (proving that nym is of proper form)
	UTilde                    *big.Int                                 // proof random data for U (proving that U is of proper form)
	commitmentsOfAttrsProvers []*commitmentzkp.DFCommitmentOpeningProver
}

func NewUserCredentialReceiver(cm *CredentialManager) *UserCredentialReceiver {
	commitmentsOfAttrsProvers := make([]*commitmentzkp.DFCommitmentOpeningProver, len(cm.commitmentsOfAttrs))
	for i, _ := range cm.commitmentsOfAttrs {
		prover := commitmentzkp.NewDFCommitmentOpeningProver(cm.attrsCommitters[i],
			cm.Params.ChallengeSpace)
		commitmentsOfAttrsProvers[i] = prover
	}

	return &UserCredentialReceiver{
		CredentialManager:         cm,
		commitmentsOfAttrsProvers: commitmentsOfAttrsProvers,
	}
}

// setU sets r.U = S^v1 * R_1^m_1 * ... * R_NumAttrs^m_NumAttrs (mod n) where only hiddenAttrs are used and
// where v1 is from +-{0,1}^(NLength + SecParam)
func (r *UserCredentialReceiver) setU() *big.Int {
	exp := big.NewInt(int64(r.CredentialManager.Params.NLength + r.CredentialManager.Params.SecParam))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	v1 := common.GetRandomIntAlsoNeg(b)
	r.CredentialManager.v1 = v1

	group := groups.NewQRSpecialRSAPublic(r.CredentialManager.PubKey.N)
	U := group.Exp(r.CredentialManager.PubKey.S, v1)

	for i, attr := range r.CredentialManager.hiddenAttrs {
		t := group.Exp(r.CredentialManager.PubKey.RsHidden[i], attr) // R_i^m_i
		U = group.Mul(U, t)
	}
	r.U = U

	return v1
}

// getNymProofRandomData returns proof random data for nym.
func (rcv *UserCredentialReceiver) getNymProofRandomData() (*big.Int, error) {
	// use Schnorr with two bases for proving that you know nym opening:
	bases := []*big.Int{
		rcv.CredentialManager.PubKey.PedersenParams.Group.G,
		rcv.CredentialManager.PubKey.PedersenParams.H,
	}
	committer := rcv.CredentialManager.nymCommitter
	val, r := committer.GetDecommitMsg() // val is actually master key
	secrets := []*big.Int{val, r}

	prover, err := dlogproofs.NewSchnorrProver(rcv.CredentialManager.PubKey.PedersenParams.Group, secrets[:], bases[:],
		committer.Commitment)
	if err != nil {
		return nil, fmt.Errorf("error when creating Schnorr prover: %s", err)
	}
	rcv.nymProver = prover

	nymTilde := prover.GetProofRandomData()
	return nymTilde, nil
}

func (r *UserCredentialReceiver) getUProofRandomData() (*big.Int, error) {
	group := groups.NewQRSpecialRSAPublic(r.CredentialManager.PubKey.N)
	// secrets are [attr_1, ..., attr_L, v1]
	secrets := append(r.CredentialManager.hiddenAttrs, r.CredentialManager.v1)

	// bases are [R_1, ..., R_L, S]
	bases := append(r.CredentialManager.PubKey.RsHidden, r.CredentialManager.PubKey.S)

	prover := qrspecialrsaproofs.NewRepresentationProver(group, r.CredentialManager.Params.SecParam,
		secrets[:], bases[:], r.U)
	r.UProver = prover

	// boundary for m_tilde
	b_m := r.CredentialManager.Params.AttrBitLen + r.CredentialManager.Params.SecParam + r.CredentialManager.Params.HashBitLen + 1
	// boundary for v1
	b_v1 := r.CredentialManager.Params.NLength + 2*r.CredentialManager.Params.SecParam + r.CredentialManager.Params.HashBitLen

	boundaries := make([]int, len(r.CredentialManager.PubKey.RsHidden))
	for i := 0; i < len(r.CredentialManager.PubKey.RsHidden); i++ {
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
func (r *UserCredentialReceiver) GetChallenge(nym, nonceOrg *big.Int) *big.Int {
	context := r.CredentialManager.PubKey.GetContext()
	l := []*big.Int{context, r.U, nym, nonceOrg}
	l = append(l, r.CredentialManager.commitmentsOfAttrs...) // TODO: add other values

	return common.Hash(l...)
}

func (r *UserCredentialReceiver) getCredentialRequestProofRandomfData() (*big.Int, *big.Int, error) {
	nymProofRandomData, err := r.getNymProofRandomData()
	if err != nil {
		return nil, nil, fmt.Errorf("error when obtaining nym proof random data: %v", err)
	}

	UProofRandomData, err := r.getUProofRandomData()
	if err != nil {
		return nil, nil, fmt.Errorf("error when obtaining U proof random data: %v", err)
	}

	return nymProofRandomData, UProofRandomData, nil
}

func (r *UserCredentialReceiver) getCredentialRequestProofData(challenge *big.Int) ([]*big.Int, []*big.Int, error) {
	return r.nymProver.GetProofData(challenge), r.UProver.GetProofData(challenge), nil
}

func (r *UserCredentialReceiver) getCommitmentsOfAttrsProof(challenge *big.Int) []*commitmentzkp.DFOpeningProof {
	commitmentsOfAttrsProofs := make([]*commitmentzkp.DFOpeningProof, len(r.commitmentsOfAttrsProvers))
	for i, prover := range r.commitmentsOfAttrsProvers {
		proofRandomData := prover.GetProofRandomData()
		proofData1, proofData2 := prover.GetProofData(challenge)
		commitmentsOfAttrsProofs[i] = commitmentzkp.NewDFOpeningProof(proofRandomData, challenge,
			proofData1, proofData2)
	}

	return commitmentsOfAttrsProofs
}

type CredentialRequest struct {
	NymProof                 *dlogproofs.SchnorrProof
	U                        *big.Int
	UProof                   *qrspecialrsaproofs.RepresentationProof
	CommitmentsOfAttrsProofs []*commitmentzkp.DFOpeningProof
	Nonce                    *big.Int
}

func NewCredentialRequest(nymProof *dlogproofs.SchnorrProof, U *big.Int,
	UProof *qrspecialrsaproofs.RepresentationProof, commitmentsOfAttrsProofs []*commitmentzkp.DFOpeningProof,
	nonce *big.Int) *CredentialRequest {
	return &CredentialRequest{
		NymProof: nymProof,
		U:        U,
		UProof:   UProof,
		CommitmentsOfAttrsProofs: commitmentsOfAttrsProofs,
		Nonce: nonce,
	}
}

// GetCredentialRequest computes U and returns CredentialRequest which contains:
// - proof data for proving that nym was properly generated,
// - U and proof data that U was properly generated,
// - proof data for proving the knowledge of opening for commitments of attributes (for those attributes
// for which the committed value is known).
func (r *UserCredentialReceiver) GetCredentialRequest(nym *big.Int, nonceOrg *big.Int) (*CredentialRequest, error) {
	r.setU()
	nymProofRandomData, UProofRandomData, err := r.getCredentialRequestProofRandomfData()
	if err != nil {
		return nil, err
	}

	challenge := r.GetChallenge(nym, nonceOrg)
	nymProofData, UProofData, err := r.getCredentialRequestProofData(challenge)
	if err != nil {
		return nil, err
	}

	commitmentsOfAttrsProofs := r.getCommitmentsOfAttrsProof(challenge)

	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(r.CredentialManager.Params.SecParam)), nil)
	nonce := common.GetRandomInt(b)

	return NewCredentialRequest(dlogproofs.NewSchnorrProof(nymProofRandomData, challenge, nymProofData),
		r.U, qrspecialrsaproofs.NewRepresentationProof(UProofRandomData, challenge, UProofData),
		commitmentsOfAttrsProofs, nonce), nil
}
