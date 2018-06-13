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
	User      *User
	v1        *big.Int // v1 is the random element in U, which is constructed also from clPubKey.R_list and attrs
	U         *big.Int
	nymProver *dlogproofs.SchnorrProver // for proving that nym is of the proper form
	// TODO: not sure what would be the most appropriate name for UProver and UTilde
	UProver                   *qrspecialrsaproofs.RepresentationProver // for proving that U is of the proper form
	nymTilde                  *big.Int                                 // proof random data for nym (proving that nym is of proper form)
	UTilde                    *big.Int                                 // proof random data for U (proving that U is of proper form)
	commitmentsOfAttrsProvers []*commitmentzkp.DFCommitmentOpeningProver
}

func NewUserCredentialReceiver(user *User) *UserCredentialReceiver {
	commitmentsOfAttrsProvers := make([]*commitmentzkp.DFCommitmentOpeningProver, len(user.commitmentsOfAttrs))
	for i, _ := range user.commitmentsOfAttrs {
		prover := commitmentzkp.NewDFCommitmentOpeningProver(user.attrsCommitters[i],
			user.Params.ChallengeSpace)
		commitmentsOfAttrsProvers[i] = prover
	}

	return &UserCredentialReceiver{
		User: user,
		commitmentsOfAttrsProvers: commitmentsOfAttrsProvers,
	}
}

// setU sets r.U = S^v1 * R_1^m_1 * ... * R_NumAttrs^m_NumAttrs (mod n) where only hiddenAttrs are used and
// where v1 is from +-{0,1}^(NLength + SecParam)
func (r *UserCredentialReceiver) setU() *big.Int {
	exp := big.NewInt(int64(r.User.Params.NLength + r.User.Params.SecParam))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	v1 := common.GetRandomIntAlsoNeg(b)
	r.v1 = v1

	group := groups.NewQRSpecialRSAPublic(r.User.PubKey.N)
	U := group.Exp(r.User.PubKey.S, v1)

	for i, attr := range r.User.hiddenAttrs {
		t := group.Exp(r.User.PubKey.RsHidden[i], attr) // R_i^m_i
		U = group.Mul(U, t)
	}
	r.U = U

	return U
}

// getNymProofRandomData return proof random data for nym.
func (rcv *UserCredentialReceiver) getNymProofRandomData(nymId int32) (*big.Int, error) {
	// use Schnorr with two bases for proving that you know nym opening:
	bases := []*big.Int{
		rcv.User.PedersenParams.Group.G,
		rcv.User.PedersenParams.H,
	}
	committer := rcv.User.Committers[nymId]
	val, r := committer.GetDecommitMsg() // val is actually master key
	secrets := []*big.Int{val, r}

	prover, err := dlogproofs.NewSchnorrProver(rcv.User.PedersenParams.Group, secrets[:], bases[:],
		committer.Commitment)
	if err != nil {
		return nil, fmt.Errorf("error when creating Schnorr prover: %s", err)
	}
	rcv.nymProver = prover

	nymTilde := prover.GetProofRandomData()
	return nymTilde, nil
}

func (r *UserCredentialReceiver) getUProofRandomData() (*big.Int, error) {
	group := groups.NewQRSpecialRSAPublic(r.User.PubKey.N)
	// secrets are [attr_1, ..., attr_L, v1]
	secrets := append(r.User.hiddenAttrs, r.v1)

	// bases are [R_1, ..., R_L, S]
	bases := append(r.User.PubKey.RsHidden, r.User.PubKey.S)

	prover := qrspecialrsaproofs.NewRepresentationProver(group, r.User.Params.SecParam,
		secrets[:], bases[:], r.U)
	r.UProver = prover

	// boundary for m_tilde
	b_m := r.User.Params.AttrBitLen + r.User.Params.SecParam + r.User.Params.HashBitLen + 1
	// boundary for v1
	b_v1 := r.User.Params.NLength + 2*r.User.Params.SecParam + r.User.Params.HashBitLen

	boundaries := make([]int, len(r.User.PubKey.RsHidden))
	for i := 0; i < len(r.User.PubKey.RsHidden); i++ {
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
	context := r.User.PubKey.GetContext()
	l := []*big.Int{context, r.U, nym, nonceOrg}
	l = append(l, r.User.commitmentsOfAttrs...)

	return common.Hash(l...)
}

func (r *UserCredentialReceiver) getCredentialRequestProofRandomfData(nymId int32) (*big.Int, *big.Int, error) {
	nymProofRandomData, err := r.getNymProofRandomData(nymId)
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
	commitmentsOfAttrsProofs := make([]*commitmentzkp.DFOpeningProof, len(r.User.attrsCommitters))
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
}

func NewCredentialRequest(nymProof *dlogproofs.SchnorrProof, U *big.Int,
	UProof *qrspecialrsaproofs.RepresentationProof, commitmentsOfAttrsProofs []*commitmentzkp.DFOpeningProof) *CredentialRequest {
	return &CredentialRequest{
		NymProof: nymProof,
		U:        U,
		UProof:   UProof,
		CommitmentsOfAttrsProofs: commitmentsOfAttrsProofs,
	}
}

// GetCredentialRequest computes U and returns CredentialRequest which contains:
// - proof data for proving that nym was properly generated,
// - U and proof data that U was properly generated,
// - proof data for proving the knowledge of opening for commitments of attributes (for those attributes
// for which the committed value is known).
func (r *UserCredentialReceiver) GetCredentialRequest(nym *Nym, nonceOrg *big.Int) (*CredentialRequest, error) {
	r.setU()
	nymProofRandomData, UProofRandomData, err := r.getCredentialRequestProofRandomfData(nym.Id)
	if err != nil {
		return nil, err
	}

	challenge := r.GetChallenge(nym.Commitment, nonceOrg)
	nymProofData, UProofData, err := r.getCredentialRequestProofData(challenge)
	if err != nil {
		return nil, err
	}

	commitmentsOfAttrsProofs := r.getCommitmentsOfAttrsProof(challenge)

	return NewCredentialRequest(dlogproofs.NewSchnorrProof(nymProofRandomData, challenge, nymProofData),
		r.U, qrspecialrsaproofs.NewRepresentationProof(UProofRandomData, challenge, UProofData),
		commitmentsOfAttrsProofs), nil
}

func (r *UserCredentialReceiver) GetNonce() *big.Int {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(r.User.Params.SecParam)), nil)
	return common.GetRandomInt(b)
}

func (r *UserCredentialReceiver) VerifyCredential(c *Credential,
	AProof *qrspecialrsaproofs.RepresentationProof, n2 *big.Int) (bool, error) {
	// check bit length of e:
	b1 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(r.User.Params.EBitLen-1)), nil)
	b22 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(r.User.Params.E1BitLen-1)), nil)
	b2 := new(big.Int).Add(b1, b22)

	if (c.e.Cmp(b1) != 1) || (b2.Cmp(c.e) != 1) {
		return false, fmt.Errorf("e is not of the proper bit length")
	}
	// check that e is prime
	if !c.e.ProbablyPrime(20) {
		return false, fmt.Errorf("e is not prime")
	}

	v := new(big.Int).Add(r.v1, c.v11)
	group := groups.NewQRSpecialRSAPublic(r.User.PubKey.N)
	// denom = S^v * R_1^attr_1 * ... * R_j^attr_j
	denom := group.Exp(r.User.PubKey.S, v) // s^v
	for i := 0; i < len(r.User.knownAttrs); i++ {
		t1 := group.Exp(r.User.PubKey.RsKnown[i], r.User.knownAttrs[i])
		denom = group.Mul(denom, t1)
	}

	for i := 0; i < len(r.User.committedAttrs); i++ {
		t1 := group.Exp(r.User.PubKey.RsCommitted[i], r.User.commitmentsOfAttrs[i])
		denom = group.Mul(denom, t1)
	}

	for i := 0; i < len(r.User.hiddenAttrs); i++ {
		t1 := group.Exp(r.User.PubKey.RsHidden[i], r.User.hiddenAttrs[i])
		denom = group.Mul(denom, t1)
	}

	denomInv := group.Inv(denom)
	Q := group.Mul(r.User.PubKey.Z, denomInv)
	Q1 := group.Exp(c.A, c.e)
	if Q1.Cmp(Q) != 0 {
		return false, fmt.Errorf("Q should be A^e (mod n)")
	}

	// verify signature proof:
	credentialVerifier := qrspecialrsaproofs.NewRepresentationVerifier(group, r.User.Params.SecParam)
	credentialVerifier.SetProofRandomData(AProof.ProofRandomData, []*big.Int{Q}, c.A)
	// check challenge
	context := r.User.PubKey.GetContext()
	c := common.Hash(context, Q, c.A, AProof.ProofRandomData, n2)
	if AProof.Challenge.Cmp(c) != 0 {
		return false, fmt.Errorf("challenge is not correct")
	}

	credentialVerifier.SetChallenge(AProof.Challenge)
	return credentialVerifier.Verify(AProof.ProofData), nil
}
