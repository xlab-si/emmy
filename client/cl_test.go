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
	"math/big"
	"testing"
	/*
		"time"

		"github.com/stretchr/testify/assert"
		"github.com/xlab-si/emmy/config"
		"github.com/xlab-si/emmy/server"
	*/
	"fmt"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/cl"
)

// TestCL requires a running server.
func TestCL(t *testing.T) {

	clParamSizes := cl.GetDefaultParamSizes()

	pubKey := new(cl.PubKey)
	cl.ReadGob("testdata/clPubKey.gob", pubKey)

	knownAttrs := []*big.Int{big.NewInt(7), big.NewInt(6), big.NewInt(5), big.NewInt(22)}
	committedAttrs := []*big.Int{big.NewInt(9), big.NewInt(17)}
	hiddenAttrs := []*big.Int{big.NewInt(11), big.NewInt(13), big.NewInt(19)}
	credManager, err := cl.NewCredentialManager(clParamSizes, pubKey, knownAttrs, committedAttrs, hiddenAttrs)
	if err != nil {
		t.Errorf("error when creating a user: %v", err)
	}

	clClient, err := NewCLClient(testGrpcClientConn)
	if err != nil {
		t.Errorf("Error when initializing NewCLClient")
	}

	credIssueNonceOrg, err := clClient.GetCredentialIssueNonce()

	credentialRequest, err := credManager.GetCredentialRequest(credIssueNonceOrg)
	if err != nil {
		t.Errorf("error when generating credential request: %v", err)
	}

	fmt.Println("++++++++++++++++++")
	fmt.Println(credentialRequest)

}
