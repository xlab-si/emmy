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
	"fmt"
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

	// TODO: change API - move issuer into org, receiver into user
	orgCredentialIssuer, err := NewOrgCredentialIssuer(org, nym.Commitment, user.knownAttrs,
		user.commitmentsOfAttrs)
	if err != nil {
		t.Errorf("error when creating credential issuer: %v", err)
	}
	nonceOrg := orgCredentialIssuer.GetNonce()

	userCredentialReceiver := NewUserCredentialReceiver(user)
	credentialRequest, err := userCredentialReceiver.GetCredentialRequest(nym, nonceOrg)
	if err != nil {
		t.Errorf("error when generating credential request: %v", err)
	}

	// user needs to send to the issuer:
	// (nonceUser, challenge, nymProofRandomData, nymProofData, UProofRandomData, UProofData, commitmentsOfAttrs,
	// commitmentsOfAttrsProofs)

	verified := orgCredentialIssuer.VerifyCredentialRequest(credentialRequest)
	assert.Equal(t, true, verified, "credential request sent to the credential issuer not correct")

	nonceUser := userCredentialReceiver.GetNonce()
	credential, AProof := orgCredentialIssuer.IssueCredential(nonceUser)

	userVerified, err := userCredentialReceiver.VerifyCredential(credential, AProof, nonceUser)
	if err != nil {
		t.Errorf("error when verifying credential: %v", err)
	}

	assert.Equal(t, true, userVerified, "credential issuance failed")

	nonceUser1 := userCredentialReceiver.GetNonce()
	newKnownAttrs := []*big.Int{big.NewInt(17), big.NewInt(18), big.NewInt(19), big.NewInt(27)}
	user.UpdateCredential(newKnownAttrs)
	credential1, AProof1 := orgCredentialIssuer.UpdateCredential(nonceUser1, newKnownAttrs)

	userVerified, err = userCredentialReceiver.VerifyCredential(credential1, AProof1, nonceUser1)
	if err != nil {
		t.Errorf("error when verifying updated credential: %v", err)
	}

	assert.Equal(t, true, userVerified, "credential update failed")

	nonce := org.GetNonce()
	proof, err := user.BuildCredentialProof(credential, nonce)
	if err != nil {
		t.Errorf("error when building credential proof: %v", err)
	}

	fmt.Println(proof)
}
