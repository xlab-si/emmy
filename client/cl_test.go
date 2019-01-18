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

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/cl"
)

// TestCL requires a running server.
func TestCL(t *testing.T) {

	params := cl.GetDefaultParamSizes()

	pubKey := new(cl.PubKey)
	cl.ReadGob("testdata/clPubKey.gob", pubKey)

	masterSecret := pubKey.GenerateUserMasterSecret()

	rawCred, err := GetCredentialStructure(testGrpcClientConn)
	if err != nil {
		t.Errorf("error when retrieving credential structure: %v", err)
	}
	// fill credential with values:
	attrValues := map[int]string{0: "Jack", 1: "M", 2: "true", 3: "122"}
	err = rawCred.SetAttributeValues(attrValues)
	if err != nil {
		t.Errorf("error when setting attribute values: %v", err)
	}

	credManager, err := cl.NewCredManager(params, pubKey, masterSecret, rawCred)
	if err != nil {
		t.Errorf("error when creating a credential manager: %v", err)
	}

	credManagerPath := "../client/testdata/credManager.gob"
	cl.WriteGob(credManagerPath, credManager)

	client, err := NewCLClient(testGrpcClientConn)
	if err != nil {
		t.Errorf("Error when initializing NewCLClient")
	}

	cred, err := client.IssueCredential(credManager)
	if err != nil {
		t.Errorf("error when calling IssueCred: %v", err)
	}

	// create new CredManager (updating or proving usually does not happen at the same time
	// as issuing)
	cl.ReadGob(credManagerPath, credManager)

	acceptableCreds, err := GetAcceptableCredentials(testGrpcClientConn)
	if err != nil {
		t.Errorf("error when retrieving acceptable credentials: %v", err)
	}
	revealedAttrIndices := acceptableCreds["org1"]

	proved, err := client.ProveCredential(credManager, cred, revealedAttrIndices)
	if err != nil {
		t.Errorf("error when proving possession of a credential: %v", err)
	}
	assert.True(t, proved, "possesion of a credential proof failed")

	attrValues = map[int]string{0: "John", 1: "M", 2: "true", 3: "122"}
	rawCred.SetAttributeValues(attrValues)

	cred1, err := client.UpdateCredential(credManager, rawCred)
	if err != nil {
		t.Errorf("error when updating credential: %v", err)
	}

	proved1, err := client.ProveCredential(credManager, cred1, revealedAttrIndices)
	if err != nil {
		t.Errorf("error when proving possession of an updated credential: %v", err)
	}

	assert.True(t, proved1, "possesion of an updated credential proof failed")
}
