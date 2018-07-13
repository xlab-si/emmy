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
	params := GetDefaultParamSizes()

	orgName := "organization 1"
	org, err := NewOrg(orgName, params)
	if err != nil {
		t.Errorf("error when generating CL org: %v", err)
	}

	knownAttrs := []*big.Int{big.NewInt(7), big.NewInt(6), big.NewInt(5), big.NewInt(22)}
	committedAttrs := []*big.Int{big.NewInt(9), big.NewInt(17)}
	hiddenAttrs := []*big.Int{big.NewInt(11), big.NewInt(13), big.NewInt(19)}
	credManager, err := NewCredentialManager(params, org.PubKey, knownAttrs, committedAttrs, hiddenAttrs)
	if err != nil {
		t.Errorf("error when creating a user: %v", err)
	}

	credIssueNonceOrg := org.GetCredentialIssueNonce()

	credReq, err := credManager.GetCredentialRequest(credIssueNonceOrg)
	if err != nil {
		t.Errorf("error when generating credential request: %v", err)
	}

	credential, AProof, err := org.IssueCredential(credManager.nym, credManager.knownAttrs,
		credManager.commitmentsOfAttrs, credReq)
	if err != nil {
		t.Errorf("error when issuing credential: %v", err)
	}

	userVerified, err := credManager.VerifyCredential(credential, AProof)
	if err != nil {
		t.Errorf("error when verifying credential: %v", err)
	}
	assert.Equal(t, true, userVerified, "credential proof not valid")

	// Before updating a credential, create a new Org object (obtaining and updating
	// credential usually don't happen at the same time)
	org, err = NewOrgFromParams(orgName, params, org.PubKey, org.SecKey)
	if err != nil {
		t.Errorf("error when generating CL org: %v", err)
	}

	newKnownAttrs := []*big.Int{big.NewInt(17), big.NewInt(18), big.NewInt(19), big.NewInt(27)}
	credManager.UpdateCredential(newKnownAttrs)
	credential1, AProof1, err := org.UpdateCredential(credManager.nym, credReq.Nonce, newKnownAttrs)
	if err != nil {
		t.Errorf("error when updating credential: %v", err)
	}

	userVerified, err = credManager.VerifyCredential(credential1, AProof1)
	if err != nil {
		t.Errorf("error when verifying updated credential: %v", err)
	}

	assert.Equal(t, true, userVerified, "credential update failed")

	// TODO: before proving the possesion of a credential, create a new User object (obtaining and proving
	// credential usually don't happen at the same time) - this means passing attributes and v1 into NewUser

	nonce := org.GetProveCredentialNonce()
	randCred, proof, err := credManager.BuildCredentialProof(credential1, nonce)
	if err != nil {
		t.Errorf("error when building credential proof: %v", err)
	}

	cVerified, err := org.ProveCredential(randCred.A, proof, newKnownAttrs)
	if err != nil {
		t.Errorf("error when verifying credential: %v", err)
	}

	assert.Equal(t, true, cVerified, "credential verification failed")
}
