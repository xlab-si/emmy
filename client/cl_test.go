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

package client

import (
	"testing"
	//"math/big"
	/*
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/server"
	*/
	//"github.com/xlab-si/emmy/crypto/zkp/schemes/cl"
	"fmt"
)

// TestCL requires a running server.
func TestCL(t *testing.T) {

	/*
	clParamSizes := cl.GetDefaultParamSizes()

	orgName := "organization 1"
	org, err := cl.NewOrg(orgName, clParamSizes)
	if err != nil {
		t.Errorf("error when generating CL org: %v", err)
	}

	knownAttrs := []*big.Int{big.NewInt(7), big.NewInt(6), big.NewInt(5), big.NewInt(22)}
	committedAttrs := []*big.Int{big.NewInt(9), big.NewInt(17)}
	hiddenAttrs := []*big.Int{big.NewInt(11), big.NewInt(13), big.NewInt(19)}
	user, err := cl.NewUser(clParamSizes, org.PubKey, org.PedersenReceiver.Params, knownAttrs, committedAttrs,
		hiddenAttrs)
	if err != nil {
		t.Errorf("error when creating a user: %v", err)
	}

	nym, err := user.GenerateNym()
	if err != nil {
		t.Errorf("error when generating nym: %v", err)
	}
	*/

	clClient, err := NewCLClient(testGrpcClientConn)
	if err != nil {
		t.Errorf("Error when initializing NewCLClient")
	}

	bla, err := clClient.GetCredentialIssueNonce()

	fmt.Println("++++++++++++++++++")
	fmt.Println(err)

	fmt.Println("??")
	fmt.Println(bla)

	fmt.Println(clClient)
}
