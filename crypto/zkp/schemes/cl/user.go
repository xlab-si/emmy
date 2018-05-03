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
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
)

type User struct {
	CLParamSizes   *CLParamSizes
	CLPubKey       *CLPubKey
	PedersenParams *commitments.PedersenParams               // for pseudonyms - nym is a commitment to the master secret
	Committers     map[string]*commitments.PedersenCommitter // for generating nyms
	masterSecret   *big.Int
	attrs [] *big.Int
	v1 *big.Int // TODO: probably this would go under struct something like UserCredentialIssue
	U *big.Int // TODO: probably this would go under struct something like UserCredentialIssue
}

func NewUser(clParamSizes *CLParamSizes, clPubKey *CLPubKey, pedersenParams *commitments.PedersenParams) *User {

	//committer := commitments.NewDamgardFujisakiCommitter(clPubKey.N, clPubKey.S, clPubKey.Z,
	//	clPubKey.N, clParamSizes.SecParam)

	return &User{
		CLParamSizes:   clParamSizes,
		CLPubKey:       clPubKey,
		Committers:     make(map[string]*commitments.PedersenCommitter),
		PedersenParams: pedersenParams,
		attrs: []*big.Int{big.NewInt(7), big.NewInt(6), big.NewInt(5)}, // TODO attributes should be read from somewhere and the structure should be loaded too
	}
}

func (u *User) GenerateMasterSecret() {
	u.masterSecret = common.GetRandomInt(u.PedersenParams.Group.Q)
}

// GetU returns U = S^v1 * R_1^m_1 * ... * R_NumAttrs^m_NumAttrs (mod n) where v1 is from +-{0,1}^(NLength + SecParam)
func (u *User) GetU() *big.Int { // TODO: should be SetU?
	b := new(big.Int).Exp(big.NewInt(2),
		big.NewInt(int64(u.CLParamSizes.NLength+u.CLParamSizes.SecParam)), nil)
	v1 := common.GetRandomIntAlsoNeg(b)
	u.v1 = v1

	group := groups.NewQRSpecialRSAPublic(u.CLPubKey.N)
	U := group.Exp(u.CLPubKey.S, v1)

	// the number of attributes, type (A_k - issuer knows an attribute, A_c - issuer knows
	// a commitment to the attribute, A_h - issuer does not know the attribute)
	for i, attr := range u.attrs {
		t := group.Exp(u.CLPubKey.R_NumAttrs[i], attr) // R_i^m_i
		U = group.Mul(U, t)
	}
	u.U = U

	return U
}

// GetNymProofRandomData return proof random data for nym.
func (u *User) GetNymProofRandomData(nymName string) (*big.Int, error) {
	// use Schnorr with two bases for proving that you know nym opening:
	bases := []*big.Int{u.PedersenParams.Group.G, u.PedersenParams.H}
	committer := u.Committers[nymName]
	val, r := committer.GetDecommitMsg() // val is actually master key
	secrets := []*big.Int{val, r}

	prover, err := dlogproofs.NewSchnorrProver(u.PedersenParams.Group, secrets[:], bases[:], committer.Commitment)
	if err != nil {
		return nil, fmt.Errorf("error when creating Schnorr prover: %s", err)
	}

	proofRandomData := prover.GetProofRandomData()
	return proofRandomData, nil
}

func (u *User) GetUProofRandomData() (*big.Int, error) {
	group := groups.NewQRSpecialRSAPublic(u.CLPubKey.N)
	// secrets are [v1, attr_1, ..., attr_L]
	secrets := make([]*big.Int, len(u.CLPubKey.R_NumAttrs) + 1)
	secrets[0] = u.v1
	for i := 0; i < len(u.CLPubKey.R_NumAttrs); i++ {
		secrets[i+1] = u.attrs[i]
	}

	// bases are [S, R_1, ..., R_L]
	bases := make([]*big.Int, len(u.CLPubKey.R_NumAttrs) + 1)
	bases[0] = u.CLPubKey.S
	for i := 0; i < len(u.CLPubKey.R_NumAttrs); i++ {
		bases[i+1] = u.CLPubKey.R_NumAttrs[i]
	}

	prover := qrspecialrsaproofs.NewRepresentationProver(group, u.CLParamSizes.SecParam,
		secrets[:], bases[:], u.U)

	// boundary for v1
	b_v1 := u.CLParamSizes.NLength + 2*u.CLParamSizes.SecParam + u.CLParamSizes.HashBitLen
	// boundary for m_tilde
	b_m := u.CLParamSizes.AttrBitLen + u.CLParamSizes.SecParam + u.CLParamSizes.HashBitLen + 1

	boundaries := make([]int, len(u.CLPubKey.R_NumAttrs) + 1)
	boundaries[0] = b_v1
	for i := 0; i < len(u.CLPubKey.R_NumAttrs); i++ {
		boundaries[i+1] = b_m
	}

	//U_tilde := prover.GetProofRandomData()
	U_tilde, err := prover.GetProofRandomDataGivenBoundaries(boundaries) // TODO: alsoNeg
	if err != nil {
		return nil, fmt.Errorf("error when generating representation proof random data: %s", err)
	}

	return U_tilde, nil
}

// GetChallenge returns Hash(context||U||nym||U_tilde||nym_tilde||n1). Thus, Fiat-Shamir is used to
// generate a challenge, instead of asking verifier to generate it.
func (u *User) GetChallenge(U, nym, n1 *big.Int) *big.Int {
	return common.Hash(U, nym, n1)
}

// GenerateNym creates a pseudonym to be used with a given organization. Multiple pseudonyms
// can be generated for the same organization (on the contrary domain pseudonym can be only
// one per organization - not implemented yet). Authentication can be done with respect to
// the pseudonym or not (depends on the server configuration).
func (u *User) GenerateNym(nymName string) (*big.Int, error) {
	committer := commitments.NewPedersenCommitter(u.PedersenParams)
	com, err := committer.GetCommitMsg(u.masterSecret)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen commitment: %s", err)
	}
	u.Committers[nymName] = committer
	return com, nil
}
