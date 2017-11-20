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

package test

import (
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	"math/big"
	"testing"
)

// TestPseudonymsys requires a running server (it is started in communication_test.go).
func TestPseudonymsys(t *testing.T) {
	group := config.LoadGroup("pseudonymsys")
	caClient, err := client.NewPseudonymsysCAClient(testGrpcClientConn)
	if err != nil {
		t.Errorf("Error when initializing NewPseudonymsysCAClient")
	}

	userSecret := config.LoadPseudonymsysUserSecret("user1", "dlog")

	p := group.Exp(group.G, userSecret) // this is user's public key
	masterNym := pseudonymsys.NewPseudonym(group.G, p)
	caCertificate, err := caClient.ObtainCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA")
	}

	// usually the endpoint is different from the one used for CA:
	c1, err := client.NewPseudonymsysClient(testGrpcClientConn)
	nym1, err := c1.GenerateNym(userSecret, caCertificate)
	if err != nil {
		t.Errorf(err.Error())
	}

	orgName := "org1"
	h1, h2 := config.LoadPseudonymsysOrgPubKeys(orgName)
	orgPubKeys := pseudonymsys.NewOrgPubKeys(h1, h2)
	credential, err := c1.ObtainCredential(userSecret, nym1, orgPubKeys)
	if err != nil {
		t.Errorf(err.Error())
	}

	// register with org2
	// create a client to communicate with org2
	caClient1, err := client.NewPseudonymsysCAClient(testGrpcClientConn)
	caCertificate1, err := caClient1.ObtainCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA")
	}

	c2, err := client.NewPseudonymsysClient(testGrpcClientConn)
	nym2, err := c2.GenerateNym(userSecret, caCertificate1)
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
