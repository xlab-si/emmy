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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCLIssue(t *testing.T) {
	clParamSizes := GetDefaultParamSizes()

	orgName := "organization 1"
	org, err := NewOrg(orgName, clParamSizes)
	if err != nil {
		t.Errorf("error when generating CL org: %v", err)
	}

	knownAttrs := []*big.Int{big.NewInt(7), big.NewInt(6), big.NewInt(5), big.NewInt(22)}
	committedAttrs := []*big.Int{big.NewInt(9), big.NewInt(17)}
	hiddenAttrs := []*big.Int{big.NewInt(11), big.NewInt(13), big.NewInt(19)}
	user, err := NewUser(clParamSizes, org.PubKey, org.PedersenReceiver.Params, knownAttrs, committedAttrs,
		hiddenAttrs)
	if err != nil {
		t.Errorf("error when creating a user: %v", err)
	}

	// TODO: if there are more than one organizations, each can have its own PedersenParams (where
	// nyms are generated, and nyms need to be managed per organization
	nym, err := user.GenerateNym()
	if err != nil {
		t.Errorf("error when generating nym: %v", err)
	}

	orgCredentialIssuer, err := NewOrgCredentialIssuer(org, nym.Commitment, user.knownAttrs,
		user.commitmentsOfAttrs)
	if err != nil {
		t.Errorf("error when creating credential issuer: %v", err)
	}
	nonceOrg := orgCredentialIssuer.GetNonce()

	userCredentialReceiver := NewUserCredentialReceiver(user)
	nymProofData, U, UProofData, commitmentsOfAttrsProofs, err :=
		userCredentialReceiver.GetCredentialRequest(nym, nonceOrg)
	if err != nil {
		t.Errorf("error when generating credential request: %v", err)
	}

	// user needs to send to the issuer:
	// (nonceUser, challenge, nymProofRandomData, nymProofData, UProofRandomData, UProofData, commitmentsOfAttrs,
	// commitmentsOfAttrsProofs)

	verified := orgCredentialIssuer.VerifyCredentialRequest(nymProofData, U, UProofData, commitmentsOfAttrsProofs)
	assert.Equal(t, true, verified, "credential request sent to the credential issuer not correct")

	nonceUser := userCredentialReceiver.GetNonce()
	// TODO: implement credential struct when implementing update credential
	A, e, v11, AProof := orgCredentialIssuer.IssueCredential(nonceUser)

	userVerified, err := userCredentialReceiver.VerifyCredential(A, e, v11, AProof, nonceUser)
	if err != nil {
		t.Errorf("error when verifying credential: %v", err)
	}

	assert.Equal(t, true, userVerified, "credential issuance failed")
}
