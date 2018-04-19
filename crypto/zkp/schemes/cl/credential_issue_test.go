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

	org, err := NewOrg(clParamSizes)
	if err != nil {
		t.Errorf("error when generating CL org: %v", err)
	}

	user := NewUser(clParamSizes, org.PubKey, org.PedersenReceiver.Params)
	//user.GenerateMasterSecret()


	n1 := org.GetNonce()
	fmt.Println(n1)

	U := user.GetU()
	// the user must now prove that U was properly computed:




	fmt.Println(U)
	fmt.Println("================================")

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