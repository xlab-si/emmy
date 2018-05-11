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
	User      *User
	v1        *big.Int // v1 is the random element in U, which is constructed also from clPubKey.R_list and attrs
	U         *big.Int
	nymProver *dlogproofs.SchnorrProver // for proving that nym is of the proper form
	// TODO: not sure what would be the most appropriate name for UProver and UTilde - currently
	// they have upper case U as it is in paper
	UProver  *qrspecialrsaproofs.RepresentationProver // for proving that U is of the proper form
	nymTilde *big.Int                                 // proof random data for nym (proving that nym is of proper form)
	UTilde   *big.Int                                 // proof random data for U (proving that U is of proper form)
}

func NewUserIssueCredentialProver(user *User) *UserIssueCredentialProver {
	return &UserIssueCredentialProver{
		User: user,
	}
}

// GetU returns U = S^v1 * R_1^m_1 * ... * R_NumAttrs^m_NumAttrs (mod n) where v1 is from +-{0,1}^(NLength + SecParam)
func (u *UserIssueCredentialProver) GetU() *big.Int { // TODO: should be SetU?
	b := new(big.Int).Exp(big.NewInt(2),
		big.NewInt(int64(u.User.ParamSizes.NLength+u.User.ParamSizes.SecParam)), nil)
	v1 := common.GetRandomIntAlsoNeg(b)
	u.v1 = v1

	group := groups.NewQRSpecialRSAPublic(u.User.PubKey.N)
	U := group.Exp(u.User.PubKey.S, v1)

	// the number of attributes, type (A_k - issuer knows an attribute, A_c - issuer knows
	// a commitment to the attribute, A_h - issuer does not know the attribute)
	// TODO: currently only for A_k
	for i, attr := range u.User.attrs {
		t := group.Exp(u.User.PubKey.R_list[i], attr) // R_i^m_i
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
	group := groups.NewQRSpecialRSAPublic(u.User.PubKey.N)
	// secrets are [attr_1, ..., attr_L, v1]
	secrets := append(u.User.attrs, u.v1)

	// bases are [R_1, ..., R_L, S]
	bases := append(u.User.PubKey.R_list, u.User.PubKey.S)

	prover := qrspecialrsaproofs.NewRepresentationProver(group, u.User.ParamSizes.SecParam,
		secrets[:], bases[:], u.U)
	u.UProver = prover

	// boundary for m_tilde
	b_m := u.User.ParamSizes.AttrBitLen + u.User.ParamSizes.SecParam + u.User.ParamSizes.HashBitLen + 1
	// boundary for v1
	b_v1 := u.User.ParamSizes.NLength + 2*u.User.ParamSizes.SecParam + u.User.ParamSizes.HashBitLen

	boundaries := make([]int, len(u.User.PubKey.R_list))
	for i := 0; i < len(u.User.PubKey.R_list); i++ {
		boundaries[i] = b_m
	}
	boundaries = append(boundaries, b_v1)

	UTilde, err := prover.GetProofRandomDataGivenBoundaries(boundaries, true)
	if err != nil {
		return nil, fmt.Errorf("error when generating representation proof random data: %s", err)
	}

	return UTilde, nil
}

// GetChallenge returns Hash(context||U||nym||U_tilde||nym_tilde||n1). Thus, Fiat-Shamir is used to
// generate a challenge, instead of asking verifier to generate it.
func (u *UserIssueCredentialProver) GetChallenge(U, nym, n1 *big.Int) *big.Int {
	context := u.User.PubKey.GetContext()
	return common.Hash(context, U, nym, n1)
}

func (u *UserIssueCredentialProver) GetProofData(challenge *big.Int) ([]*big.Int, []*big.Int) {
	return u.nymProver.GetProofData(challenge), u.UProver.GetProofData(challenge)
}

func (u *UserIssueCredentialProver) GetNonce() *big.Int {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(u.User.ParamSizes.SecParam)), nil)
	return common.GetRandomInt(b)
}

func (u *UserIssueCredentialProver) verifySignatureProof(AProofData *qrspecialrsaproofs.RepresentationProof) (bool, error) {
	// TODO
	return false, nil
}

func (u *UserIssueCredentialProver) Verify(A, e, v11 *big.Int) (bool, error) {
	// check bit length of e:
	b1 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(u.User.ParamSizes.SizeE - 1)), nil)
	b21 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(u.User.ParamSizes.SizeE - 1)), nil)
	b22 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(u.User.ParamSizes.SizeE1 - 1)), nil)
	b2 := new(big.Int).Add(b21, b22)
	if (e.Cmp(b1) != 1) || (b2.Cmp(e) != 1) {
		return false, fmt.Errorf("e is not of the proper bit length")
	}
	// check that e is prime
	if !e.ProbablyPrime(20) {
		return false, fmt.Errorf("e is not prime")
	}

	v := new(big.Int).Add(u.v1, v11)
	group := groups.NewQRSpecialRSAPublic(u.User.PubKey.N)
	// denom = S^v * R_1^attr_1 * ... * R_j^attr_j where only attributes from A_k (known)
	denom := group.Exp(u.User.PubKey.S, v) // s^v
	/*
	for i := 0; i < len(u.User.attrs); i++ { // TODO: from not known attributes
		t1 := group.Exp(u.User.PubKey.R_list[i], u.User.attrs[i]) // TODO: R_list should be replaced with those that correspond to A_k
		denom = group.Mul(denom, t1)
	}
	*/

	denomInv := group.Inv(denom)
	Q := group.Mul(u.User.PubKey.Z, denomInv)
	Q1 := group.Exp(A, e)
	if Q1.Cmp(Q) != 0 {
		return false, fmt.Errorf("Q should be A^e (mod n)")
	}

	// verify signature proof:

	return true, nil
}
