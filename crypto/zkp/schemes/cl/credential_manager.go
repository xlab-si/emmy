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

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/commitments"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
)

// CredentialManager should be created by a user when a credential is to be issued, updated or proved.
// If a new credential under a new nym is needed, new CredentialManager instance is needed.
type CredentialManager struct {
	Params             *Params
	PubKey             *PubKey
	nymCommitter       *commitments.PedersenCommitter // nym is actually a commitment to masterSecret
	Nym                *big.Int
	masterSecret       *big.Int
	KnownAttrs         []*big.Int // attributes that are known to the credential receiver and issuer
	committedAttrs     []*big.Int // attributes for which the issuer knows only commitment
	CommitmentsOfAttrs []*big.Int // commitments of committedAttrs
	hiddenAttrs        []*big.Int // attributes which are known only to the credential receiver
	// V1 is a random element in credential - it is generated in GetCredentialRequest and needed when
	// proving the possesion of a credential - this is why it is stored in User and not in UserCredentialReceiver
	V1                        *big.Int                                   // v1 is random element in U; U = S^v1 * R_i^m_i where m_i are hidden attributes
	attrsCommitters           []*commitments.DamgardFujisakiCommitter    // committers for committedAttrs
	commitmentsOfAttrsProvers []*commitmentzkp.DFCommitmentOpeningProver // for proving that you know how to open CommitmentsOfAttrs
	CredReqNonce              *big.Int
}

func checkAttributesLength(attributes []*big.Int, params *Params) bool {
	for _, attr := range attributes {
		if attr.BitLen() > params.AttrBitLen {
			return false
		}
	}

	return true
}

func NewCredentialManager(params *Params, pubKey *PubKey, masterSecret *big.Int, knownAttrs, committedAttrs,
	hiddenAttrs []*big.Int) (*CredentialManager, error) {
	if !checkAttributesLength(knownAttrs, params) || !checkAttributesLength(committedAttrs, params) ||
		!checkAttributesLength(hiddenAttrs, params) {
		return nil, fmt.Errorf("attributes length not ok")
	}

	attrsCommitters := make([]*commitments.DamgardFujisakiCommitter, len(committedAttrs))
	commitmentsOfAttrs := make([]*big.Int, len(committedAttrs))
	for i, attr := range committedAttrs {
		committer := commitments.NewDamgardFujisakiCommitter(pubKey.N1, pubKey.G, pubKey.H,
			pubKey.N1, params.SecParam)
		com, err := committer.GetCommitMsg(attr)
		if err != nil {
			return nil, fmt.Errorf("error when creating Pedersen commitment: %s", err)
		}
		commitmentsOfAttrs[i] = com
		attrsCommitters[i] = committer
	}
	commitmentsOfAttrsProvers := make([]*commitmentzkp.DFCommitmentOpeningProver, len(commitmentsOfAttrs))
	for i, _ := range commitmentsOfAttrs {
		prover := commitmentzkp.NewDFCommitmentOpeningProver(attrsCommitters[i], params.ChallengeSpace)
		commitmentsOfAttrsProvers[i] = prover
	}

	credManager := CredentialManager{
		Params:                    params,
		PubKey:                    pubKey,
		KnownAttrs:                knownAttrs,
		committedAttrs:            committedAttrs,
		hiddenAttrs:               hiddenAttrs,
		CommitmentsOfAttrs:        commitmentsOfAttrs,
		attrsCommitters:           attrsCommitters,
		commitmentsOfAttrsProvers: commitmentsOfAttrsProvers,
		masterSecret:              masterSecret,
	}
	credManager.generateNym()

	return &credManager, nil
}

func NewCredentialManagerFromExisting(nym, v1, credReqNonce *big.Int, params *Params, pubKey *PubKey, masterSecret *big.Int,
	knownAttrs, committedAttrs, hiddenAttrs, commitmentsOfAttrs []*big.Int) (*CredentialManager, error) {

	// nymCommitter is needed only for IssueCredential (when proving that nym can be opened), so we do not need it here
	// the same for attrsCommitters

	return &CredentialManager{
		Params:             params,
		PubKey:             pubKey,
		KnownAttrs:         knownAttrs,
		committedAttrs:     committedAttrs,
		hiddenAttrs:        hiddenAttrs,
		CommitmentsOfAttrs: commitmentsOfAttrs,
		masterSecret:       masterSecret,
		Nym:                nym,
		V1:                 v1,
		CredReqNonce:       credReqNonce,
	}, nil
}

// generateNym creates a pseudonym to be used with a given organization. Authentication can be done
// with respect to the pseudonym or not.
func (m *CredentialManager) generateNym() error {
	committer := commitments.NewPedersenCommitter(m.PubKey.PedersenParams)
	nym, err := committer.GetCommitMsg(m.masterSecret)
	if err != nil {
		return fmt.Errorf("error when creating Pedersen commitment: %s", err)
	}
	m.Nym = nym
	m.nymCommitter = committer

	return nil
}

// GetCredentialRequest computes U and returns CredentialRequest which contains:
// - proof data for proving that nym was properly generated,
// - U and proof data that U was properly generated,
// - proof data for proving the knowledge of opening for commitments of attributes (for those attributes
// for which the committed value is known).
func (m *CredentialManager) GetCredentialRequest(nonceOrg *big.Int) (*CredentialRequest, error) {
	U, v1 := m.computeU()
	m.V1 = v1
	nymProver, uProver, err := m.getCredReqProvers(U)
	if err != nil {
		return nil, err
	}

	challenge := m.getCredReqChallenge(U, m.Nym, nonceOrg)
	commitmentsOfAttrsProofs := m.getCommitmentsOfAttrsProof(challenge)

	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(m.Params.SecParam)), nil)
	nonce := common.GetRandomInt(b)
	m.CredReqNonce = nonce

	uProofRandomData, err := m.getUProofRandomData(uProver)
	if err != nil {
		return nil, err
	}

	return NewCredentialRequest(m.Nym, m.KnownAttrs, m.CommitmentsOfAttrs,
		dlogproofs.NewSchnorrProof(nymProver.GetProofRandomData(), challenge,
			nymProver.GetProofData(challenge)), U,
		qrspecialrsaproofs.NewRepresentationProof(uProofRandomData, challenge,
			uProver.GetProofData(challenge)),
		commitmentsOfAttrsProofs, nonce), nil
}

func (m *CredentialManager) VerifyCredential(cred *Credential,
	AProof *qrspecialrsaproofs.RepresentationProof) (bool, error) {
	// check bit length of e:
	b1 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(m.Params.EBitLen-1)), nil)
	b22 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(m.Params.E1BitLen-1)), nil)
	b2 := new(big.Int).Add(b1, b22)

	if (cred.E.Cmp(b1) != 1) || (b2.Cmp(cred.E) != 1) {
		return false, fmt.Errorf("e is not of the proper bit length")
	}
	// check that e is prime
	if !cred.E.ProbablyPrime(20) {
		return false, fmt.Errorf("e is not prime")
	}

	v := new(big.Int).Add(m.V1, cred.V11)
	group := groups.NewQRSpecialRSAPublic(m.PubKey.N)
	// denom = S^v * R_1^attr_1 * ... * R_j^attr_j
	denom := group.Exp(m.PubKey.S, v) // s^v
	for i := 0; i < len(m.KnownAttrs); i++ {
		t1 := group.Exp(m.PubKey.RsKnown[i], m.KnownAttrs[i])
		denom = group.Mul(denom, t1)
	}

	for i := 0; i < len(m.committedAttrs); i++ {
		t1 := group.Exp(m.PubKey.RsCommitted[i], m.CommitmentsOfAttrs[i])
		denom = group.Mul(denom, t1)
	}

	for i := 0; i < len(m.hiddenAttrs); i++ {
		t1 := group.Exp(m.PubKey.RsHidden[i], m.hiddenAttrs[i])
		denom = group.Mul(denom, t1)
	}

	denomInv := group.Inv(denom)
	Q := group.Mul(m.PubKey.Z, denomInv)
	Q1 := group.Exp(cred.A, cred.E)
	if Q1.Cmp(Q) != 0 {
		return false, fmt.Errorf("Q should be A^e (mod n)")
	}

	// verify signature proof:
	ver := qrspecialrsaproofs.NewRepresentationVerifier(group, m.Params.SecParam)
	ver.SetProofRandomData(AProof.ProofRandomData, []*big.Int{Q}, cred.A)
	// check challenge
	context := m.PubKey.GetContext()
	c := common.Hash(context, Q, cred.A, AProof.ProofRandomData, m.CredReqNonce)
	if AProof.Challenge.Cmp(c) != 0 {
		return false, fmt.Errorf("challenge is not correct")
	}

	ver.SetChallenge(AProof.Challenge)

	return ver.Verify(AProof.ProofData), nil
}

func (m *CredentialManager) UpdateCredential(knownAttrs []*big.Int) {
	m.KnownAttrs = knownAttrs
}

func (m *CredentialManager) randomizeCredential(cred *Credential) *Credential {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(m.Params.NLength+m.Params.SecParam)), nil)
	r := common.GetRandomInt(b)
	group := groups.NewQRSpecialRSAPublic(m.PubKey.N)
	t := group.Exp(m.PubKey.S, r)
	A := group.Mul(cred.A, t) // cred.A * S^r
	t = new(big.Int).Mul(cred.E, r)
	v11 := new(big.Int).Sub(cred.V11, t) // cred.v11 - e*r (in Z)

	t = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(m.Params.EBitLen-1)), nil)

	return NewCredential(A, cred.E, v11)
}

func (m *CredentialManager) GetCredProofChallenge(credProofRandomData, nonceOrg *big.Int) *big.Int {
	context := m.PubKey.GetContext()
	l := []*big.Int{context, credProofRandomData, nonceOrg}
	//l = append(l, ...) // TODO: add other values

	return common.Hash(l...)
}

func (m *CredentialManager) BuildCredentialProof(cred *Credential, revealedKnownAttrsIndices,
revealedCommitmentsOfAttrsIndices []int, nonceOrg *big.Int) (*Credential,
	*qrspecialrsaproofs.RepresentationProof, error) {
	if m.V1 == nil {
		return nil, nil, fmt.Errorf("v1 is not set (generated in GetCredentialRequest)")
	}
	rCred := m.randomizeCredential(cred)
	// Z = cred.A^cred.e * S^cred.v11 * R_1^m_1 * ... * R_l^m_l
	// Z = rCred.A^rCred.e * S^rCred.v11 * R_1^m_1 * ... * R_l^m_l
	group := groups.NewQRSpecialRSAPublic(m.PubKey.N)

	bases := []*big.Int{}
	unrevealedKnownAttrs := []*big.Int{}
	unrevealedCommitmentsOfAttrs := []*big.Int{}
	for i := 0; i < len(m.KnownAttrs); i++ {
		if !contains(revealedKnownAttrsIndices, i)  {
			bases = append(bases, m.PubKey.RsKnown[i])
			unrevealedKnownAttrs = append(unrevealedKnownAttrs, m.KnownAttrs[i])
		}
	}
	for i := 0; i < len(m.CommitmentsOfAttrs); i++ {
		if !contains(revealedCommitmentsOfAttrsIndices, i)  {
			bases = append(bases, m.PubKey.RsCommitted[i])
			unrevealedCommitmentsOfAttrs = append(unrevealedCommitmentsOfAttrs, m.CommitmentsOfAttrs[i])
		}
	}
	bases = append(bases, m.PubKey.RsHidden...)
	bases = append(bases, rCred.A)
	bases = append(bases, m.PubKey.S)

	secrets := append(unrevealedKnownAttrs, unrevealedCommitmentsOfAttrs...)
	secrets = append(secrets, m.hiddenAttrs...)
	secrets = append(secrets, rCred.E)
	v := new(big.Int).Add(rCred.V11, m.V1)
	secrets = append(secrets, v)

	denom := big.NewInt(1)
	for i := 0; i < len(m.KnownAttrs); i++ {
		if contains(revealedKnownAttrsIndices, i) {
			t1 := group.Exp(m.PubKey.RsKnown[i], m.KnownAttrs[i])
			denom = group.Mul(denom, t1)
		}
	}

	for i := 0; i < len(m.committedAttrs); i++ {
		if contains(revealedCommitmentsOfAttrsIndices, i) {
			t1 := group.Exp(m.PubKey.RsCommitted[i], m.CommitmentsOfAttrs[i])
			denom = group.Mul(denom, t1)
		}
	}
	denomInv := group.Inv(denom)
	y := group.Mul(m.PubKey.Z, denomInv)

	prover := qrspecialrsaproofs.NewRepresentationProver(group, m.Params.SecParam,
		secrets, bases, y)

	// boundary for m_tilde
	b_m := m.Params.AttrBitLen + m.Params.SecParam + m.Params.HashBitLen
	// boundary for e
	b_e := m.Params.EBitLen + m.Params.SecParam + m.Params.HashBitLen
	// boundary for v1
	b_v1 := m.Params.VBitLen + m.Params.SecParam + m.Params.HashBitLen

	boundaries := []int{}
	for i := 0; i < len(unrevealedKnownAttrs); i++ {
		boundaries = append(boundaries, b_m)
	}
	for i := 0; i < len(unrevealedCommitmentsOfAttrs); i++ {
		boundaries = append(boundaries, b_m)
	}
	for _, _ = range m.PubKey.RsHidden {
		boundaries = append(boundaries, b_m)
	}
	boundaries = append(boundaries, b_e)
	boundaries = append(boundaries, b_v1)

	proofRandomData, err := prover.GetProofRandomDataGivenBoundaries(boundaries, true)
	if err != nil {
		return nil, nil, fmt.Errorf("error when generating representation proof random data: %s", err)
	}

	challenge := m.GetCredProofChallenge(proofRandomData, nonceOrg)
	proofData := prover.GetProofData(challenge)

	return rCred, qrspecialrsaproofs.NewRepresentationProof(proofRandomData, challenge, proofData), nil
}
