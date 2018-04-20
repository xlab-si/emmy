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
)

type User struct {
	CLParamSizes   *CLParamSizes
	CLPubKey       *CLPubKey
	PedersenParams *commitments.PedersenParams               // for pseudonyms - nym is a commitment to the master secret
	Committers     map[string]*commitments.PedersenCommitter // for generating nyms
	masterSecret   *big.Int
}

func NewUser(clParamSizes *CLParamSizes, clPubKey *CLPubKey, pedersenParams *commitments.PedersenParams) *User {

	//committer := commitments.NewDamgardFujisakiCommitter(clPubKey.N, clPubKey.S, clPubKey.Z,
	//	clPubKey.N, clParamSizes.SecParam)

	return &User{
		CLParamSizes:   clParamSizes,
		CLPubKey:       clPubKey,
		Committers:     make(map[string]*commitments.PedersenCommitter),
		PedersenParams: pedersenParams,
	}
}

func (u *User) GenerateMasterSecret() {
	u.masterSecret = common.GetRandomInt(u.PedersenParams.Group.Q)
}

// GetU returns U = S^v1 * R_1^m_1 * ... * R_NumAttrs^m_NumAttrs (mod n) where v1 is from +-{0,1}^(NLength + SecParam)
func (u *User) GetU() *big.Int {
	b := new(big.Int).Exp(big.NewInt(2),
		big.NewInt(int64(u.CLParamSizes.NLength+u.CLParamSizes.SecParam)), nil)
	v1 := common.GetRandomIntAlsoNeg(b)

	group := groups.NewQRSpecialRSAPublic(u.CLPubKey.N)
	U := group.Exp(u.CLPubKey.S, v1)

	// TODO: attributes should be read from somewhere and the structure should be loaded too -
	// the number of attributes, type (A_k - issuer knows an attribute, A_c - issuer knows
	// a commitment to the attribute, A_h - issuer does not know the attribute)
	attrs := []*big.Int{big.NewInt(7), big.NewInt(6), big.NewInt(5)}
	for i, attr := range attrs {
		t := group.Exp(u.CLPubKey.R_NumAttrs[i], attr) // R_i^m_i
		U = group.Mul(U, t)
	}

	return U
}

// GetNymUProofRandomData return proof random data for nym and U.
func (u *User) GetNymUProofRandomData(nymName string) ([]*big.Int, error) {
	// random values are from +-{0,1}^(AttrBitLen + NLen + HashBitLen + 1)
	b := new(big.Int).Exp(big.NewInt(2),
		big.NewInt(int64(
			u.CLParamSizes.AttrBitLen+u.CLParamSizes.NLength+u.CLParamSizes.HashBitLen+1)), nil)

	// for nym:
	nymR := common.GetRandomIntAlsoNeg(b)
	fmt.Println(nymR)

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
	fmt.Println(proofRandomData)

	// use RepresentationProof for attributes:

	return nil, nil
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
