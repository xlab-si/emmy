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

	n1 := org.GetNonce()
	fmt.Println(n1)

	U := user.GetU()
	// the user must now prove that U was properly computed:

	fmt.Println(U)
	fmt.Println("================================")

	// nym and U are ready, let's now prepare data to prove that nym and U are properly generated:

	nymProofRandomData, err := user.GetNymProofRandomData(nymName)
	if err != nil {
		t.Errorf("error when obtaining nym proof random data: %v", err)
	}
	fmt.Println(nymProofRandomData)

	UProofRandomData, err := user.GetUProofRandomData()
	if err != nil {
		t.Errorf("error when obtaining U proof random data: %v", err)
	}
	fmt.Println(UProofRandomData)

	context := org.PubKey.GetContext()
	fmt.Println(context)

	challenge := user.GetChallenge(U, nym, n1)
	fmt.Println(challenge)


	/*
		nym, err := user.GenerateNym("testOrg")
		if err != nil {
			t.Errorf("error when generating nym: %v", err)
		}

		fmt.Println(nym)
	*/

	/*
		if err != nil {
			assert.Equal(t, proved, false, "ECDLogEquality proof failed: %v", err)
		}

		assert.Equal(t, proved, true, "ECDLogEquality does not work correctly")
	*/
}
