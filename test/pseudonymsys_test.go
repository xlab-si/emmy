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
	"github.com/xlab-si/emmy/server"
	"math/big"
	"testing"
	"io"
	"fmt"
	"encoding/base64"
	"crypto/rand"
	"time"
)

// TestPseudonymsys requires a running server (it is started in communication_test.go).
func TestPseudonymsys(t *testing.T) {
	group := config.LoadGroup("pseudonymsys")
	caClient, err := client.NewPseudonymsysCAClient(testGrpcClientConn)
	if err != nil {
		t.Errorf("Error when initializing NewPseudonymsysCAClient")
	}

	// usually the endpoint is different from the one used for CA:
	c1, err := client.NewPseudonymsysClient(testGrpcClientConn)
	userSecret := c1.GenerateMasterKey()

	p := group.Exp(group.G, userSecret) // this is user's public key
	masterNym := pseudonymsys.NewPseudonym(group.G, p)
	caCertificate, err := caClient.ObtainCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA")
	}

	//nym generation should fail with invalid registration key
	_, err = c1.GenerateNym(userSecret, caCertificate, "029uywfh9udni")
	assert.NotNil(t, err, "Should produce an error")

	regKey, err := getRegistrationKey()
	if err != nil {
		t.Errorf("Error getting registration key: %s", err.Error())
	}

	nym1, err := c1.GenerateNym(userSecret, caCertificate, regKey)
	if err != nil {
		t.Errorf(err.Error())
	}

	//nym generation should fail the second time with the same registration key
	_, err = c1.GenerateNym(userSecret, caCertificate, regKey)
	assert.NotNil(t, err, "Should produce an error")

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

	regKey, err = getRegistrationKey()
	if err != nil {
		t.Errorf("Error getting registration key: %s", err.Error())
	}

	// c2 connects to the same server as c1, so what we're really testing here is
	// using transferCredential to authenticate with the same organization and not
	// transferring credentials to another organization
	c2, err := client.NewPseudonymsysClient(testGrpcClientConn)
	nym2, err := c2.GenerateNym(userSecret, caCertificate1, regKey)
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

func getRegistrationKey() (string, error) {
	registrationManager, err := server.NewRegistrationManager(config.LoadRegistrationDBAddress())
	if err != nil {
		return "", err
	}

	buffer := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buffer); err != nil {
		return "", fmt.Errorf("Error reading random bytes: %v", err)
	}
	regKey := base64.StdEncoding.EncodeToString(buffer)
	err = registrationManager.Set(regKey, regKey, time.Minute).Err()

	return regKey, nil
}