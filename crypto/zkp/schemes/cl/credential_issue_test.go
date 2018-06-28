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

func TestCL(t *testing.T) {
	clParamSizes := GetDefaultParamSizes()

	orgName := "organization 1"
	org, err := NewOrg(orgName, clParamSizes)
	if err != nil {
		t.Errorf("error when generating CL org: %v", err)
	}

	knownAttrs := []*big.Int{big.NewInt(7), big.NewInt(6), big.NewInt(5), big.NewInt(22)}
	committedAttrs := []*big.Int{big.NewInt(9), big.NewInt(17)}
	hiddenAttrs := []*big.Int{big.NewInt(11), big.NewInt(13), big.NewInt(19)}
	user, err := NewUser(clParamSizes, org.PubKey, knownAttrs, committedAttrs, hiddenAttrs)
	if err != nil {
		t.Errorf("error when creating a user: %v", err)
	}

	nym, err := user.GenerateNym()
	if err != nil {
		t.Errorf("error when generating nym: %v", err)
	}

	credIssueNonceOrg := org.GetCredentialIssueNonce()

	credentialRequest, err := user.GetCredentialRequest(nym, credIssueNonceOrg)
	if err != nil {
		t.Errorf("error when generating credential request: %v", err)
	}

	// user needs to send to the issuer:
	// (nonceUser, challenge, nymProofRandomData, nymProofData, UProofRandomData, UProofData, commitmentsOfAttrs,
	// commitmentsOfAttrsProofs)

	verified, err := org.VerifyCredentialRequest(nym, user.knownAttrs, user.commitmentsOfAttrs, credentialRequest)
	if err != nil {
		t.Errorf("error when verifying credential request: %v", err)
	}
	assert.Equal(t, true, verified, "credential request sent to the credential issuer not correct")

	credIssueNonceUser := user.GetCredentialIssueNonce()
	credential, AProof := org.IssueCredential(credIssueNonceUser)

	userVerified, err := user.VerifyCredential(credential, AProof)
	if err != nil {
		t.Errorf("error when verifying credential: %v", err)
	}

	assert.Equal(t, true, userVerified, "credential issuance failed")

	updateCredentialNonce := user.GetCredentialIssueNonce()
	newKnownAttrs := []*big.Int{big.NewInt(17), big.NewInt(18), big.NewInt(19), big.NewInt(27)}
	user.UpdateCredential(newKnownAttrs)
	credential1, AProof1 := org.UpdateCredential(updateCredentialNonce, newKnownAttrs)

	userVerified, err = user.VerifyCredential(credential1, AProof1)
	if err != nil {
		t.Errorf("error when verifying updated credential: %v", err)
	}

	assert.Equal(t, true, userVerified, "credential update failed")

	// TODO: before proving the possesion of a credential, create a new User object (obtaining and proving
	// credential usually don't happen at the same time) - this means passing attributes and v1 into NewUser

	nonce := org.GetProveCredentialNonce()
	randCred, proof, err := user.BuildCredentialProof(credential1, nonce)
	if err != nil {
		t.Errorf("error when building credential proof: %v", err)
	}

	cVerified, err := org.ProveCredential(randCred.A, proof, newKnownAttrs)
	if err != nil {
		t.Errorf("error when verifying credential: %v", err)
	}

	assert.Equal(t, true, cVerified, "credential verification failed")
}
