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
	Params             *CLParams
	PubKey             *PubKey
	PedersenParams     *commitments.PedersenParams              // for pseudonyms - nym is a commitment to the master secret
	Committers         map[int32]*commitments.PedersenCommitter // for generating nyms
	masterSecret       *big.Int
	knownAttrs         []*big.Int                              // attributes that are known to the credential receiver and issuer
	committedAttrs     []*big.Int                              // attributes for which the issuer knows only commitment
	hiddenAttrs        []*big.Int                              // attributes which are known only to the credential receiver
	attrsCommitters    []*commitments.DamgardFujisakiCommitter // committers for committedAttrs
	commitmentsOfAttrs []*big.Int                              // commitments of committedAttrs
}

func checkAttributesLength(attributes []*big.Int, params *CLParams) bool {
	for _, attr := range attributes {
		if attr.BitLen() > params.AttrBitLen {
			return false
		}
	}

	return true
}

func NewUser(clParams *CLParams, clPubKey *PubKey, pedersenParams *commitments.PedersenParams,
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

func (u *User) UpdateCredential(knownAttrs []*big.Int) {
	u.knownAttrs = knownAttrs
}

func (u *User) randomizeCredential(cred *Credential) *Credential {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(u.Params.NLength + u.Params.SecParam)), nil)
	r := common.GetRandomInt(b)
	group := groups.NewQRSpecialRSAPublic(u.PubKey.N)
	t := group.Exp(u.PubKey.S, r)
	A := group.Mul(cred.A, t) // cred.A * S^r
	t = new(big.Int).Mul(cred.e, r)
	v11 := new(big.Int).Sub(cred.v11, t)// cred.v11 - e*r (in Z)

	t = new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(u.Params.EBitLen-1)), nil)
	e := new(big.Int).Sub(cred.e, t) // cred.e - 2^(EBitLen-1)

	return NewCredential(A, e, v11) // TODO: or return the old e?
}

func (u *User) GetChallenge(credProofRandomData, nonceOrg *big.Int) *big.Int {
	context := u.PubKey.GetContext()
	l := []*big.Int{context, credProofRandomData}
	//l = append(l, ...) // TODO: add other values

	return common.Hash(l...)
}

func (u *User) BuildCredentialProof(cred *Credential, nonceOrg *big.Int) (*qrspecialrsaproofs.RepresentationProof, error){
	rCred := u.randomizeCredential(cred)
	// Z = cred.A^cred.e * S^cred.v11 * R_1^m_1 * ... * R_l^m_l
	// Z = rCred.A^rCred.e * S^rCred.v11 * R_1^m_1 * ... * R_l^m_l
	group := groups.NewQRSpecialRSAPublic(u.PubKey.N)
	// bases for representation proof are: R_i, rCred.A, S
	bases := append(u.PubKey.RsKnown, u.PubKey.RsCommitted...)
	bases = append(bases, u.PubKey.RsHidden...)
	bases = append(bases, rCred.A)
	bases = append(bases, u.PubKey.S)
	// secrets are m_i (all attributes), rCred.e, rCred.v11
	secrets := append(u.knownAttrs, u.committedAttrs...)
	secrets = append(secrets, u.hiddenAttrs...)
	secrets = append(secrets, rCred.e)
	secrets = append(secrets, rCred.v11)
	prover := qrspecialrsaproofs.NewRepresentationProver(group, u.Params.SecParam,
		secrets, bases, u.PubKey.Z)

	// boundary for m_tilde
	b_m := u.Params.AttrBitLen + u.Params.SecParam + u.Params.HashBitLen
	// boundary for e1
	b_e := u.Params.EBitLen + u.Params.SecParam + u.Params.HashBitLen
	// boundary for v1
	b_v1 := u.Params.VBitLen + u.Params.SecParam + u.Params.HashBitLen

	numAttrs := len(u.PubKey.RsKnown) + len(u.PubKey.RsCommitted) + len(u.PubKey.RsHidden)
	boundaries := make([]int, numAttrs)
	for i := 0; i < numAttrs; i++ {
		boundaries[i] = b_m
	}
	boundaries = append(boundaries, b_e)
	boundaries = append(boundaries, b_v1)

	proofRandomData, err := prover.GetProofRandomDataGivenBoundaries(boundaries, true)
	if err != nil {
		return nil, fmt.Errorf("error when generating representation proof random data: %s", err)
	}

	challenge := u.GetChallenge(proofRandomData, nonceOrg)
	proofData := prover.GetProofData(challenge)

	return qrspecialrsaproofs.NewRepresentationProof(proofRandomData, challenge, proofData), nil
}

