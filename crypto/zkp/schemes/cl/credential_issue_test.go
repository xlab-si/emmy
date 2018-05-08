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

	//"github.com/stretchr/testify/assert"
	//"github.com/xlab-si/emmy/crypto/common"
	//"github.com/xlab-si/emmy/crypto/groups"
	"fmt"
)

func TestCLIssue(t *testing.T) {
	clParamSizes := GetParamSizes()
	/*
		clParams, err := GenerateParams(clParamSizes)
		if err != nil {
			t.Errorf("error when generating CL params: %v", err)
		}
	*/

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
	fmt.Println(nym)

	userIssueCredential := NewUserIssueCredentialProver(user)
	U := userIssueCredential.GetU()

	orgIssueCredential := NewOrgIssueCredentialVerifier(org, nym, U)
	n1 := orgIssueCredential.GetNonce()
	fmt.Println(n1)

	// the user must now prove that U was properly computed:

	fmt.Println(U)
	fmt.Println("================================")

	// nym and U are ready, let's now prepare data to prove that nym and U are properly generated:

	nymProofRandomData, err := userIssueCredential.GetNymProofRandomData(nymName)
	if err != nil {
		t.Errorf("error when obtaining nym proof random data: %v", err)
	}
	fmt.Println(nymProofRandomData)

	UProofRandomData, err := userIssueCredential.GetUProofRandomData()
	if err != nil {
		t.Errorf("error when obtaining U proof random data: %v", err)
	}
	fmt.Println(UProofRandomData)

	challenge := userIssueCredential.GetChallenge(U, nym, n1)

	nymProofData, UProofData := userIssueCredential.GetProofData(challenge)
	fmt.Println(nymProofData)
	fmt.Println(UProofData)

	// user needs to send to the issuer:
	// (n2, challenge, nymProofRandomData, nymProofData, UProofRandomData, UProofData)

	n2 := userIssueCredential.GetNonce()
	fmt.Println(n2)

	verified := orgIssueCredential.Verify(nymProofRandomData, UProofRandomData, challenge,
		nymProofData, UProofData)
	fmt.Println(verified)



}
