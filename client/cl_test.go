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
	"github.com/stretchr/testify/require"
	"github.com/xlab-si/emmy/crypto/cl"
)

// TestCL requires a running server.
func TestCL(t *testing.T) {
	params := cl.GetDefaultParamSizes()
	pubKey := new(cl.PubKey)
	cl.ReadGob("testdata/clPubKey.gob", pubKey)

	client, err := NewCLClient(testGrpcClientConn)
	if err != nil {
		t.Errorf("Error when initializing NewCLClient")
	}

	rc, err := client.GetCredentialStructure()
	if err != nil {
		t.Errorf("error when retrieving credential structure: %v", err)
	}

	t.Log("_--------------_________---")
	t.Log(rc.GetAttrs())

	name, _ := rc.GetAttr("name")
	err = name.UpdateValue("Jack")
	assert.NoError(t, err)
	gender, _ := rc.GetAttr("gender")
	err = gender.UpdateValue("M")
	assert.NoError(t, err)
	graduated, _ := rc.GetAttr("graduated")
	err = graduated.UpdateValue("true")
	assert.NoError(t, err)
	age, _ := rc.GetAttr("age")
	err = age.UpdateValue(50)
	assert.NoError(t, err)

	acceptableCreds, err := client.GetAcceptableCreds()
	require.NoError(t, err)
	revealedAttrs := acceptableCreds["org1"] // FIXME

	t.Log("---------------------------------")
	t.Log(revealedAttrs)

	masterSecret := pubKey.GenerateUserMasterSecret()

	cm, err := cl.NewCredManager(params, pubKey, masterSecret, rc)
	require.NoError(t, err)

	regKey := "key1"
	regKeyDB.Insert(regKey)
	cred, err := client.IssueCredential(cm, regKey)
	require.NoError(t, err)

	t.Log("_____")
	t.Log(cred)

	/*
		// create new CredManager (updating or proving usually does not happen at the same time
		// as issuing)
		cm, err = cl.NewCredManagerFromExisting(cm.Nym, cm.V1,
			cm.CredReqNonce, params.Config, pubKey, masterSecret, rc,
			cm.CommitmentsOfAttrs)
		require.NoError(t, err)

		sessKey, err := client.ProveCredential(cm, cred, revealedAttrs)
		require.NoError(t, err)
		assert.NotNil(t, sessKey, "possesion of a credential proof failed")

		// modify some attributes and get updated credential
		name, err = rc.GetAttr("name")
		err = name.UpdateValue("Jim")
		assert.NoError(t, err)

		cred1, err := client.UpdateCredential(cm, rc)
		require.NoError(t, err)

		sessKey, err = client.ProveCredential(cm, cred1, revealedAttrs)
		require.NoError(t, err)
		assert.NotNil(t, sessKey,
			"possesion of an updated credential proof failed")
	*/

}
