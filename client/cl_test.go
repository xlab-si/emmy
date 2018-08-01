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

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/cl"
)

// TestCL requires a running server.
func TestCL(t *testing.T) {

	params := cl.GetDefaultParamSizes()

	pubKey := new(cl.PubKey)
	cl.ReadGob("testdata/clPubKey.gob", pubKey)

	masterSecret := pubKey.GenerateUserMasterSecret()

	knownAttrs := []*big.Int{big.NewInt(7), big.NewInt(6), big.NewInt(5), big.NewInt(22)}
	committedAttrs := []*big.Int{big.NewInt(9), big.NewInt(17)}
	hiddenAttrs := []*big.Int{big.NewInt(11), big.NewInt(13), big.NewInt(19)}
	credManager, err := cl.NewCredentialManager(params, pubKey, masterSecret, knownAttrs, committedAttrs,
		hiddenAttrs)

	if err != nil {
		t.Errorf("error when creating a user: %v", err)
	}

	clClient, err := NewCLClient(testGrpcClientConn)
	if err != nil {
		t.Errorf("Error when initializing NewCLClient")
	}

	cred, err := clClient.IssueCredential(credManager)
	if err != nil {
		t.Errorf("error when calling IssueCredential: %v", err)
	}

	// create new CredentialManager (updating or proving usually does not happen at the same time
	// as issuing)
	credManager, err = cl.NewCredentialManagerFromExisting(credManager.Nym, credManager.V1,
		credManager.CredReqNonce, params, pubKey, masterSecret, knownAttrs, committedAttrs, hiddenAttrs,
		credManager.CommitmentsOfAttrs)
	if err != nil {
		t.Errorf("error when calling NewCredentialManagerFromExisting: %v", err)
	}

	newKnownAttrs := []*big.Int{big.NewInt(17), big.NewInt(18), big.NewInt(19), big.NewInt(27)}

	cred1, err := clClient.UpdateCredential(credManager, newKnownAttrs)
	if err != nil {
		t.Errorf("error when updating credential: %v", err)
	}

	proved, err := clClient.ProveCredential(credManager, cred, knownAttrs)
	if err != nil {
		t.Errorf("error when proving possession of a credential: %v", err)
	}
	assert.Equal(t, true, proved, "possesion of a credential proof failed")

	proved1, err := clClient.ProveCredential(credManager, cred1, newKnownAttrs)
	if err != nil {
		t.Errorf("error when proving possession of an updated credential: %v", err)
	}

	assert.Equal(t, true, proved1, "possesion of an updated credential proof failed")
}
