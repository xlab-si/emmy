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

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
)

type OrgIssueCredentialVerifier struct {
	Org      *Org
	nym *big.Int
	nymVerifier *dlogproofs.SchnorrVerifier
}

func NewOrgIssueCredentialVerifier(org *Org, nym *big.Int) *OrgIssueCredentialVerifier {
	return &OrgIssueCredentialVerifier{
		Org: org,
		nym: nym,
		nymVerifier: dlogproofs.NewSchnorrVerifier(org.PedersenReceiver.Params.Group),
	}
}

func (o *OrgIssueCredentialVerifier) GetNonce() *big.Int {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(o.Org.CLParamSizes.SecParam)), nil)
	return common.GetRandomInt(b)
}

func (o *OrgIssueCredentialVerifier) VerifyNym(nymProofRandomData, challenge *big.Int,
		nymProofData []*big.Int) bool {
	bases := []*big.Int{o.Org.PedersenReceiver.Params.Group.G, o.Org.PedersenReceiver.Params.H}
	o.nymVerifier.SetProofRandomData(nymProofRandomData, bases[:], o.nym)
	o.nymVerifier.SetChallenge(challenge)
	return o.nymVerifier.Verify(nymProofData)
}


