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
	"math/rand"
	"time"

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
)

type User struct {
	Params             *Params
	PubKey             *PubKey
	PedersenParams     *commitments.PedersenParams // for pseudonyms - nym is a commitment to the master secret
	credentialReceiver *UserCredentialReceiver
	// TODO: it might be better to have only one PedersenCommitter and simply create a new user
	// for a new nym
	Committers         map[int32]*commitments.PedersenCommitter // for generating nyms
	masterSecret       *big.Int
	knownAttrs         []*big.Int                              // attributes that are known to the credential receiver and issuer
	committedAttrs     []*big.Int                              // attributes for which the issuer knows only commitment
	hiddenAttrs        []*big.Int                              // attributes which are known only to the credential receiver
	// v1 is a random element in credential - it is generated in GetCredentialRequest and needed when
	// proving the possesion of a credential - this is why it is stored in User and not in UserCredentialReceiver
	v1        *big.Int // v1 is random element in U; U = S^v1 * R_i^m_i where m_i are hidden attributes
	attrsCommitters    []*commitments.DamgardFujisakiCommitter // committers for committedAttrs
	commitmentsOfAttrs []*big.Int                              // commitments of committedAttrs
}

func checkAttributesLength(attributes []*big.Int, params *Params) bool {
	for _, attr := range attributes {
		if attr.BitLen() > params.AttrBitLen {
			return false
		}
	}

	return true
}

func NewUser(clParams *Params, clPubKey *PubKey, pedersenParams *commitments.PedersenParams,
	knownAttrs, committedAttrs, hiddenAttrs []*big.Int) (*User, error) {
	if !checkAttributesLength(knownAttrs, clParams) || !checkAttributesLength(committedAttrs, clParams) ||
		!checkAttributesLength(hiddenAttrs, clParams) {
		return nil, fmt.Errorf("attributes length not ok")
	}

	attrsCommitters := make([]*commitments.DamgardFujisakiCommitter, len(committedAttrs))
	commitmentsOfAttrs := make([]*big.Int, len(committedAttrs))
	for i, attr := range committedAttrs {
		committer := commitments.NewDamgardFujisakiCommitter(clPubKey.N1, clPubKey.G, clPubKey.H,
			clPubKey.N1, clParams.SecParam)
		com, err := committer.GetCommitMsg(attr)
		if err != nil {
			return nil, fmt.Errorf("error when creating Pedersen commitment: %s", err)
		}
		commitmentsOfAttrs[i] = com
		attrsCommitters[i] = committer
	}
	rand.Seed(time.Now().UTC().UnixNano())

	return &User{
		Params:             clParams,
		PubKey:             clPubKey,
		Committers:         make(map[int32]*commitments.PedersenCommitter),
		PedersenParams:     pedersenParams,
		knownAttrs:         knownAttrs,
		committedAttrs:     committedAttrs,
		hiddenAttrs:        hiddenAttrs,
		commitmentsOfAttrs: commitmentsOfAttrs,
		attrsCommitters:    attrsCommitters,
		masterSecret:       common.GetRandomInt(pedersenParams.Group.Q),
	}, nil
}

type Nym struct {
	Id         int32    // nym identifier
	Commitment *big.Int // actual nym that will be known to the organisation - it is in the form of Pedersen commitment
}

func NewNym(commitment *big.Int) *Nym {
	return &Nym{
		Id:         rand.Int31(),
		Commitment: commitment,
	}
}

// GenerateNym creates a pseudonym to be used with a given organization. Multiple pseudonyms
// can be generated for the same organization (on the contrary domain pseudonym can be only
// one per organization - not implemented yet). Authentication can be done with respect to
// the pseudonym or not (depends on the server configuration).
func (u *User) GenerateNym() (*Nym, error) {
	committer := commitments.NewPedersenCommitter(u.PedersenParams)
	com, err := committer.GetCommitMsg(u.masterSecret)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen commitment: %s", err)
	}
	nym := NewNym(com)
	u.Committers[nym.Id] = committer
	return nym, nil
}

func (u *User) GetNonce() *big.Int {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(u.Params.SecParam)), nil)
	return common.GetRandomInt(b)
}

func (u *User) GetCredentialRequest(nym *Nym, nonceOrg *big.Int) (*CredentialRequest, error) {
	u.credentialReceiver = NewUserCredentialReceiver(u)
	credReq, err := u.credentialReceiver.GetCredentialRequest(nym, nonceOrg)
	if err != nil {
		return nil, err
	}
	return credReq, nil
}

func (u *User) VerifyCredential(cred *Credential,
	AProof *qrspecialrsaproofs.RepresentationProof, n2 *big.Int) (bool, error) {
	verified, err := u.credentialReceiver.VerifyCredential(cred, AProof, n2)
	if err != nil {
		return false, err
	}
	return verified, nil
}

func (u *User) UpdateCredential(knownAttrs []*big.Int) {
	u.knownAttrs = knownAttrs
}

func (u *User) randomizeCredential(cred *Credential) *Credential {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(u.Params.NLength+u.Params.SecParam)), nil)
	r := common.GetRandomInt(b)
	group := groups.NewQRSpecialRSAPublic(u.PubKey.N)
	t := group.Exp(u.PubKey.S, r)
	A := group.Mul(cred.A, t) // cred.A * S^r
	t = new(big.Int).Mul(cred.e, r)
	v11 := new(big.Int).Sub(cred.v11, t) // cred.v11 - e*r (in Z)

	t = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(u.Params.EBitLen-1)), nil)
	//e1 := new(big.Int).Sub(cred.e, t) // cred.e - 2^(EBitLen-1) // TODO: when is this needed?

	return NewCredential(A, cred.e, v11)
}

func (u *User) GetChallenge(credProofRandomData, nonceOrg *big.Int) *big.Int {
	context := u.PubKey.GetContext()
	l := []*big.Int{context, credProofRandomData, nonceOrg}
	//l = append(l, ...) // TODO: add other values

	return common.Hash(l...)
}

func (u *User) BuildCredentialProof(cred *Credential, nonceOrg *big.Int) (*Credential,
	*qrspecialrsaproofs.RepresentationProof, error) {
	if u.v1 == nil {
		return nil, nil, fmt.Errorf("v1 is not set in User (generated in GetCredentialRequest)")
	}
	rCred := u.randomizeCredential(cred)
	// Z = cred.A^cred.e * S^cred.v11 * R_1^m_1 * ... * R_l^m_l
	// Z = rCred.A^rCred.e * S^rCred.v11 * R_1^m_1 * ... * R_l^m_l
	group := groups.NewQRSpecialRSAPublic(u.PubKey.N)
	bases := append(u.PubKey.RsHidden, rCred.A)
	bases = append(bases, u.PubKey.S)
	secrets := append(u.hiddenAttrs, rCred.e)
	v := new(big.Int).Add(rCred.v11, u.v1)
	secrets = append(secrets, v)

	denom := big.NewInt(1)
	for i := 0; i < len(u.knownAttrs); i++ {
		t1 := group.Exp(u.PubKey.RsKnown[i], u.knownAttrs[i])
		denom = group.Mul(denom, t1)
	}

	for i := 0; i < len(u.committedAttrs); i++ {
		t1 := group.Exp(u.PubKey.RsCommitted[i], u.commitmentsOfAttrs[i])
		denom = group.Mul(denom, t1)
	}
	denomInv := group.Inv(denom)
	y := group.Mul(u.PubKey.Z, denomInv)

	prover := qrspecialrsaproofs.NewRepresentationProver(group, u.Params.SecParam,
		secrets, bases, y)

	// boundary for m_tilde
	b_m := u.Params.AttrBitLen + u.Params.SecParam + u.Params.HashBitLen
	// boundary for e1
	b_e := u.Params.EBitLen + u.Params.SecParam + u.Params.HashBitLen
	// boundary for v1
	b_v1 := u.Params.VBitLen + u.Params.SecParam + u.Params.HashBitLen

	boundaries := make([]int, len(u.PubKey.RsHidden))
	for i, _ := range u.PubKey.RsHidden {
		boundaries[i] = b_m
	}
	boundaries = append(boundaries, b_e)
	boundaries = append(boundaries, b_v1)

	proofRandomData, err := prover.GetProofRandomDataGivenBoundaries(boundaries, true)
	if err != nil {
		return nil, nil, fmt.Errorf("error when generating representation proof random data: %s", err)
	}

	challenge := u.GetChallenge(proofRandomData, nonceOrg)
	proofData := prover.GetProofData(challenge)

	return rCred, qrspecialrsaproofs.NewRepresentationProof(proofRandomData, challenge, proofData), nil

}
