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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCLIssue(t *testing.T) {
	clParamSizes := GetParamSizes()

	orgName := "organization 1"
	org, err := NewOrg(orgName, clParamSizes)
	if err != nil {
		t.Errorf("error when generating CL org: %v", err)
	}

	user := NewUser(clParamSizes, org.PubKey, org.PedersenReceiver.Params)
	user.GenerateMasterSecret()
	nymName := "nym1"

	// TODO: if there are more than one organizations, each can have its own PedersenParams (where
	// nyms are generated, and nyms need to be managed per organization
	nym, err := user.GenerateNym(nymName)
	if err != nil {
		t.Errorf("error when generating nym: %v", err)
	}

	userIssueCredential := NewUserIssueCredentialProver(user)
	U := userIssueCredential.GetU()

	orgIssueCredential := NewOrgIssueCredentialVerifier(org, nym, U)
	n1 := orgIssueCredential.GetNonce()

	nymProofData, UProofData, err := userIssueCredential.GetCredentialRequest(nymName, nym, U, n1)
	if err != nil {
		t.Errorf("error when generating credential request: %v", err)
	}

	// user needs to send to the issuer:
	// (n2, challenge, nymProofRandomData, nymProofData, UProofRandomData, UProofData)

	n2 := userIssueCredential.GetNonce()

	verified := orgIssueCredential.VerifyCredentialRequest(nymProofData, UProofData)
	assert.Equal(t, true, verified, "credential request sent to the credential issuer not correct")

	// TODO: only known attributes (from A_k)
	A, e, v11, AProof := orgIssueCredential.IssueCredential(user.attrs, n2)

	userVerified, err := userIssueCredential.VerifyCredential(A, e, v11, AProof, n2)
	if err != nil {
		t.Errorf("error when verifying credential: %v", err)
	}

	assert.Equal(t, true, userVerified, "credential issuance failed")
}
