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
	"crypto/rand"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
)

type OrgIssueCredentialVerifier struct {
	Org      *Org
	nym *big.Int
	U *big.Int
	n1 *big.Int
	nymVerifier *dlogproofs.SchnorrVerifier
	UVerifier *qrspecialrsaproofs.RepresentationVerifier
}

func NewOrgIssueCredentialVerifier(org *Org, nym, U *big.Int) *OrgIssueCredentialVerifier {
	return &OrgIssueCredentialVerifier{
		Org: org,
		nym: nym,
		U: U,
		nymVerifier: dlogproofs.NewSchnorrVerifier(org.PedersenReceiver.Params.Group),
		UVerifier: qrspecialrsaproofs.NewRepresentationVerifier(org.Group,
			org.CLParamSizes.SecParam),
	}
}

func (o *OrgIssueCredentialVerifier) GetNonce() *big.Int {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(o.Org.CLParamSizes.SecParam)), nil)
	n := common.GetRandomInt(b)
	o.n1 = n
	return n
}

func (o *OrgIssueCredentialVerifier) verifyNym(nymProofRandomData, challenge *big.Int,
		nymProofData []*big.Int) bool {
	bases := []*big.Int{o.Org.PedersenReceiver.Params.Group.G, o.Org.PedersenReceiver.Params.H}
	o.nymVerifier.SetProofRandomData(nymProofRandomData, bases[:], o.nym)
	o.nymVerifier.SetChallenge(challenge)
	return o.nymVerifier.Verify(nymProofData)
}

func (o *OrgIssueCredentialVerifier) verifyU(UProofRandomData, challenge *big.Int, UProofData []*big.Int) bool {
	// bases are [R_1, ..., R_L, S]
	bases := append(o.Org.PubKey.R_list, o.Org.PubKey.S)
	o.UVerifier.SetProofRandomData(UProofRandomData, bases, o.U)
	o.UVerifier.SetChallenge(challenge)
	return o.UVerifier.Verify(UProofData)
}

func (o *OrgIssueCredentialVerifier) verifyChallenge(challenge *big.Int) bool {
	context := o.Org.PubKey.GetContext()
	c := common.Hash(context, o.U, o.nym, o.n1)
	return c.Cmp(challenge) == 0
}

func (o *OrgIssueCredentialVerifier) verifyUProofDataLengths(UProofData []*big.Int) bool {
	// boundary for m_tilde
	b_m := o.Org.CLParamSizes.AttrBitLen + o.Org.CLParamSizes.SecParam + o.Org.CLParamSizes.HashBitLen + 2
	// boundary for v1_tilde
	b_v1 := o.Org.CLParamSizes.NLength + 2*o.Org.CLParamSizes.SecParam + o.Org.CLParamSizes.HashBitLen + 1

	exp := big.NewInt(int64(b_m))
	b1 := new(big.Int).Exp(big.NewInt(2), exp, nil)

	exp = big.NewInt(int64(b_v1))
	b2 := new(big.Int).Exp(big.NewInt(2), exp, nil)

	for i := 0; i < len(o.Org.PubKey.R_list); i++ {
		if UProofData[i].Cmp(b1) > 0 {
			return false
		}
	}
	if UProofData[len(o.Org.PubKey.R_list)].Cmp(b2) > 0 {
		return false
	}
	return true
}

func (o *OrgIssueCredentialVerifier) Verify(nymProofRandomData, UProofRandomData, challenge *big.Int,
		nymProofData, UProofData []*big.Int) bool {
	return o.verifyNym(nymProofRandomData, challenge, nymProofData) &&
		o.verifyU(UProofRandomData, challenge, UProofData) &&
		o.verifyChallenge(challenge) &&
		o.verifyUProofDataLengths(UProofData)
}

func (o *OrgIssueCredentialVerifier) Issue() *big.Int {
	ed, _ := rand.Prime(rand.Reader, o.Org.CLParamSizes.SizeE1 - 1)
	exp := big.NewInt(int64(o.Org.CLParamSizes.SizeE - 1))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	e := new(big.Int).Add(ed, b)

	return e
}



