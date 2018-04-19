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
	"math/big"
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"fmt"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/prometheus/client_golang/api/prometheus/v1"
)

type User struct {
	CLParamSizes *CLParamSizes
	CLPubKey *CLPubKey
	Committer *commitments.PedersenCommitter // for generating pseudonyms
	masterSecret               *big.Int
	nyms map[string]*big.Int
}

func NewUser(clParamSizes *CLParamSizes, clPubKey *CLPubKey, pedersenParams *commitments.PedersenParams) *User {
	nyms := make(map[string]*big.Int)

	//committer := commitments.NewDamgardFujisakiCommitter(clPubKey.N, clPubKey.S, clPubKey.Z,
	//	clPubKey.N, clParamSizes.SecParam)

	committer := commitments.NewPedersenCommitter(pedersenParams)

	return &User{
		CLParamSizes: clParamSizes,
		CLPubKey: clPubKey,
		Committer: committer,
		nyms: nyms,
	}
}

func (u *User) GenerateMasterSecret() {
	//u.masterSecret = common.GetRandomInt(u.CLParams.CommitmentGroup.Q)
}

// GetU returns U = S^v1 * R_1^m_1 * ... * R_NumAttrs^m_NumAttrs (mod n) where v1 is from +-{0,1}^(NLength + SecParam)
func (u *User) GetU() *big.Int {
	b := new(big.Int).Exp(big.NewInt(2),
		big.NewInt(int64(u.CLParamSizes.NLength + u.CLParamSizes.SecParam)), nil)
	v1 := common.GetRandomInt(b)
	sign := common.GetRandomInt(big.NewInt(2)) // 0 or 1
	if sign.Cmp(big.NewInt(0)) == 0 {
		v1.Neg(v1)
	}

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
func (u *User) GetNymUProofRandomData() []*big.Int {
	// random values are from +-{0,1}^(AttrBitLen + NLen + HashBitLen + 1)
	b := new(big.Int).Exp(big.NewInt(2),
		big.NewInt(int64(
			u.CLParamSizes.AttrBitLen + u.CLParamSizes.NLength + u.CLParamSizes.HashBitLen + 1)), nil)

	// for nym:
	nymR := common.GetRandomInt(b)
	sign := common.GetRandomInt(big.NewInt(2)) // 0 or 1
	if sign.Cmp(big.NewInt(0)) == 0 {
		nymR.Neg(nymR)
	}
	fmt.Println(nymR)

	// use Schnorr with two bases for nym:

	// use RepresentationProof for attributes:

	return nil
}

// GenerateNym creates a pseudonym to be used with a given organization. Multiple pseudonyms
// can be generated for the same organization (on the contrary domain pseudonym can be only
// one per organization - not implemented yet). Authentication can be done with respect to
// the pseudonym or not (depends on the server configuration).
func (u *User) GenerateNym(orgName string) (*big.Int, error) {
	com, err := u.Committer.GetCommitMsg(u.masterSecret)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen commitment: %s", err)
	}
	u.nyms[orgName] = com
	return com, nil
}



