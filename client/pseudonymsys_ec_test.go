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
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
)

func TestPseudonymsysEC(t *testing.T) {
	curveType := groups.P256
	group := groups.NewECGroup(curveType)
	caClient, err := NewPseudonymsysCAClientEC(testGrpcClientConn, curveType)
	if err != nil {
		t.Errorf("Error when initializing NewPseudonymsysCAClientEC")
	}

	// usually the endpoint is different from the one used for CA:
	c1, err := NewPseudonymsysClientEC(testGrpcClientConn, curveType)
	userSecret := c1.GenerateMasterKey()

	nymA := groups.NewECGroupElement(group.Curve.Params().Gx, group.Curve.Params().Gy)
	nymB := group.Exp(nymA, userSecret) // this is user's public key

	masterNym := pseudonymsys.NewPseudonymEC(nymA, nymB)
	caCertificate, err := caClient.ObtainCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA")
	}

	err = insertTestRegistrationKeys()
	if err != nil {
		t.Errorf("Error getting registration key: %s", err.Error())
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
	h1X, h1Y, h2X, h2Y := config.LoadPseudonymsysOrgPubKeysEC(orgName)
	h1 := groups.NewECGroupElement(h1X, h1Y)
	h2 := groups.NewECGroupElement(h2X, h2Y)
	orgPubKeys := pseudonymsys.NewOrgPubKeysEC(h1, h2)
	credential, err := c1.ObtainCredential(userSecret, nym1, orgPubKeys)
	if err != nil {
		t.Errorf(err.Error())
	}

	// register with org2
	// create a client to communicate with org2
	caClient1, err := NewPseudonymsysCAClientEC(testGrpcClientConn, curveType)
	caCertificate1, err := caClient1.ObtainCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA")
	}

	// c2 connects to the same server as c1, so what we're really testing here is
	// using transferCredential to authenticate with the same organization and not
	// transferring credentials to another organization
	c2, err := NewPseudonymsysClientEC(testGrpcClientConn, curveType)
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
