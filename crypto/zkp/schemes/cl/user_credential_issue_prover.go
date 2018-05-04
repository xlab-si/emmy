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
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
)

type UserIssueCredentialProver struct {
	User *User
	v1 *big.Int // v1 is the random element in U, which is constructed also from clPubKey.R_list and attrs
	U *big.Int
	nymProver *dlogproofs.SchnorrProver // for proving that nym is of the proper form
	UProver *qrspecialrsaproofs.RepresentationProver // for proving that U is of the proper form
	nymTilde *big.Int // proof random data for nym (proving that nym is of proper form)
	UTilde *big.Int // proof random data for U (proving that U is of proper form)
}

func NewUserIssueCredentialProver(user *User) *UserIssueCredentialProver {
	return &UserIssueCredentialProver{
		User: user,
	}
}

// GetU returns U = S^v1 * R_1^m_1 * ... * R_NumAttrs^m_NumAttrs (mod n) where v1 is from +-{0,1}^(NLength + SecParam)
func (u *UserIssueCredentialProver) GetU() *big.Int { // TODO: should be SetU?
	b := new(big.Int).Exp(big.NewInt(2),
		big.NewInt(int64(u.User.CLParamSizes.NLength+u.User.CLParamSizes.SecParam)), nil)
	v1 := common.GetRandomIntAlsoNeg(b)
	u.v1 = v1

	group := groups.NewQRSpecialRSAPublic(u.User.CLPubKey.N)
	U := group.Exp(u.User.CLPubKey.S, v1)

	// the number of attributes, type (A_k - issuer knows an attribute, A_c - issuer knows
	// a commitment to the attribute, A_h - issuer does not know the attribute)
	for i, attr := range u.User.attrs {
		t := group.Exp(u.User.CLPubKey.R_list[i], attr) // R_i^m_i
		U = group.Mul(U, t)
	}
	u.U = U

	return U
}

// GetNymProofRandomData return proof random data for nym.
func (u *UserIssueCredentialProver) GetNymProofRandomData(nymName string) (*big.Int, error) {
	// use Schnorr with two bases for proving that you know nym opening:
	bases := []*big.Int{u.User.PedersenParams.Group.G, u.User.PedersenParams.H}
	committer := u.User.Committers[nymName]
	val, r := committer.GetDecommitMsg() // val is actually master key
	secrets := []*big.Int{val, r}

	prover, err := dlogproofs.NewSchnorrProver(u.User.PedersenParams.Group, secrets[:], bases[:],
		committer.Commitment)
	if err != nil {
		return nil, fmt.Errorf("error when creating Schnorr prover: %s", err)
	}
	u.nymProver = prover

	nymTilde := prover.GetProofRandomData()
	return nymTilde, nil
}

func (u *UserIssueCredentialProver) GetUProofRandomData() (*big.Int, error) {
	group := groups.NewQRSpecialRSAPublic(u.User.CLPubKey.N)
	// secrets are [v1, attr_1, ..., attr_L]
	secrets := make([]*big.Int, len(u.User.CLPubKey.R_list) + 1)
	secrets[0] = u.v1
	for i := 0; i < len(u.User.CLPubKey.R_list); i++ {
		secrets[i+1] = u.User.attrs[i]
	}

	// bases are [S, R_1, ..., R_L]
	bases := make([]*big.Int, len(u.User.CLPubKey.R_list) + 1)
	bases[0] = u.User.CLPubKey.S
	for i := 0; i < len(u.User.CLPubKey.R_list); i++ {
		bases[i+1] = u.User.CLPubKey.R_list[i]
	}

	prover := qrspecialrsaproofs.NewRepresentationProver(group, u.User.CLParamSizes.SecParam,
		secrets[:], bases[:], u.U)
	u.UProver = prover

	// boundary for v1
	b_v1 := u.User.CLParamSizes.NLength + 2*u.User.CLParamSizes.SecParam + u.User.CLParamSizes.HashBitLen
	// boundary for m_tilde
	b_m := u.User.CLParamSizes.AttrBitLen + u.User.CLParamSizes.SecParam + u.User.CLParamSizes.HashBitLen + 1

	boundaries := make([]int, len(u.User.CLPubKey.R_list) + 1)
	boundaries[0] = b_v1
	for i := 0; i < len(u.User.CLPubKey.R_list); i++ {
		boundaries[i+1] = b_m
	}

	//UTilde := prover.GetProofRandomData()
	UTilde, err := prover.GetProofRandomDataGivenBoundaries(boundaries) // TODO: alsoNeg
	if err != nil {
		return nil, fmt.Errorf("error when generating representation proof random data: %s", err)
	}

	return UTilde, nil
}

// GetChallenge returns Hash(context||U||nym||U_tilde||nym_tilde||n1). Thus, Fiat-Shamir is used to
// generate a challenge, instead of asking verifier to generate it.
func (u *UserIssueCredentialProver) GetChallenge(U, nym, n1 *big.Int) *big.Int {
	context := u.User.CLPubKey.GetContext()
	return common.Hash(context, U, nym, n1)
}

func (u *UserIssueCredentialProver) GetProofData(challenge *big.Int) ([]*big.Int, []*big.Int) {
	return u.nymProver.GetProofData(challenge), u.UProver.GetProofData(challenge)
}

func (u *UserIssueCredentialProver) GetNonce() *big.Int {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(u.User.CLParamSizes.SecParam)), nil)
	return common.GetRandomInt(b)
}


