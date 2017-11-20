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
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	"github.com/xlab-si/emmy/types"
	"math/big"
	"testing"
)

func TestPseudonymsysEC(t *testing.T) {
	curveType := dlog.P256
	ecdlog := dlog.NewECDLog(curveType)
	caClient, err := client.NewPseudonymsysCAClientEC(testGrpcClientConn, curveType)
	if err != nil {
		t.Errorf("Error when initializing NewPseudonymsysCAClientEC")
	}

	userSecret := config.LoadPseudonymsysUserSecret("user1", "ecdlog")

	nymA := types.NewECGroupElement(ecdlog.Curve.Params().Gx, ecdlog.Curve.Params().Gy)
	nymB1, nymB2 := ecdlog.Exponentiate(nymA.X, nymA.Y, userSecret) // this is user's public key
	nymB := types.NewECGroupElement(nymB1, nymB2)

	masterNym := pseudonymsys.NewPseudonymEC(nymA, nymB)
	caCertificate, err := caClient.ObtainCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA")
	}

	// usually the endpoint is different from the one used for CA:
	c1, err := client.NewPseudonymsysClientEC(testGrpcClientConn, curveType)
	nym1, err := c1.GenerateNym(userSecret, caCertificate)
	if err != nil {
		t.Errorf(err.Error())
	}

	orgName := "org1"
	h1X, h1Y, h2X, h2Y := config.LoadPseudonymsysOrgPubKeysEC(orgName)
	h1 := types.NewECGroupElement(h1X, h1Y)
	h2 := types.NewECGroupElement(h2X, h2Y)
	orgPubKeys := pseudonymsys.NewOrgPubKeysEC(h1, h2)
	credential, err := c1.ObtainCredential(userSecret, nym1, orgPubKeys)
	if err != nil {
		t.Errorf(err.Error())
	}

	// register with org2
	// create a client to communicate with org2
	caClient1, err := client.NewPseudonymsysCAClientEC(testGrpcClientConn, curveType)
	caCertificate1, err := caClient1.ObtainCertificate(userSecret, masterNym)
	if err != nil {
		t.Errorf("Error when registering with CA")
	}

	c2, err := client.NewPseudonymsysClientEC(testGrpcClientConn, curveType)
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
