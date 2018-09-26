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
	"github.com/xlab-si/emmy/config"
)

// TestPseudonymsys requires a running server (it is started in communication_test.go).
func TestPseudonymsys(t *testing.T) {
	group := config.LoadSchnorrGroup()

	caClient, err := NewPseudonymsysCAClient(testGrpcClientConn, group)
	if err != nil {
		t.Errorf("Error when initializing NewPseudonymsysCAClient")
	}

	// usually the endpoint is different from the one used for CA:
	c1, err := NewPseudonymsysClient(testGrpcClientConn, group)
	userSecret := c1.GenerateMasterKey()

	masterNym := caClient.GenerateMasterNym(userSecret)
	caCertificate, err := caClient.GenerateCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA")
	}

	//nym generation should fail with invalid registration key
	_, err = c1.GenerateNym(userSecret, caCertificate, "029uywfh9udni")
	assert.NotNil(t, err, "Should produce an error")

	nym1, err := c1.GenerateNym(userSecret, caCertificate, "testRegKey1")
	if err != nil {
		t.Errorf(err.Error())
	}

	//nym generation should fail the second time with the same registration key
	_, err = c1.GenerateNym(userSecret, caCertificate, "testRegKey1")
	assert.NotNil(t, err, "Should produce an error")

	orgName := "org1"
	orgPubKeys := config.LoadPseudonymsysOrgPubKeys(orgName)
	credential, err := c1.ObtainCredential(userSecret, nym1, orgPubKeys)
	if err != nil {
		t.Errorf(err.Error())
	}

	// register with org2
	// create a client to communicate with org2
	caClient1, err := NewPseudonymsysCAClient(testGrpcClientConn, group)
	caCertificate1, err := caClient1.GenerateCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA: %s", err.Error())
	}

	// c2 connects to the same server as c1, so what we're really testing here is
	// using transferCredential to authenticate with the same organization and not
	// transferring credentials to another organization
	c2, err := NewPseudonymsysClient(testGrpcClientConn, group)
	nym2, err := c2.GenerateNym(userSecret, caCertificate1, "testRegKey2")
	if err != nil {
		t.Errorf(err.Error())
	}

	// Authentication should succeed
	sessionKey1, err := c2.TransferCredential(orgName, userSecret, nym2, credential)
	assert.NotNil(t, sessionKey1, "Should authenticate and obtain a valid (non-nil) session key")
	assert.Nil(t, err, "Should not produce an error")

	// Authentication should fail because the user doesn't have the right secret
	wrongUserSecret := big.NewInt(3952123123)
	sessionKey2, err := c2.TransferCredential(orgName, wrongUserSecret, nym2, credential)
	assert.Nil(t, sessionKey2, "Authentication should fail, and session key should be nil")
	assert.NotNil(t, err, "Should produce an error")
}
