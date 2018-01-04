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
	"math/big"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/encryption"
)

func TestPaillier(t *testing.T) {
	paillier := encryption.NewPaillier(1024)
	pubKey := paillier.GetPubKey()

	m := common.GetRandomInt(big.NewInt(123412341234123))
	pubPaillier := encryption.NewPubPaillier(pubKey)
	c, _ := pubPaillier.Encrypt(m)
	p, _ := paillier.Decrypt(c)

	assert.Equal(t, m, p, "Paillier encryption/decryption does not work correctly")
}

func TestCSPaillier(t *testing.T) {
	secParams := encryption.CSPaillierSecParams{
		L:        512,
		RoLength: 160,
		K:        158,
		K1:       158,
	}

	dir := config.LoadTestKeyDirFromConfig()
	secKeyPath := filepath.Join(dir, "cspaillierseckey.txt")
	pubKeyPath := filepath.Join(dir, "cspaillierpubkey.txt")

	cspaillier := encryption.NewCSPaillier(&secParams)
	cspaillier.StoreSecKey(secKeyPath)
	cspaillier.StorePubKey(pubKeyPath)

	cspaillierPub, _ := encryption.NewCSPaillierFromPubKeyFile(pubKeyPath)

	m := common.GetRandomInt(big.NewInt(8685849))
	label := common.GetRandomInt(big.NewInt(340002223232))
	u, e, v, _ := cspaillierPub.Encrypt(m, label)

	cspaillierSec, _ := encryption.NewCSPaillierFromSecKey(secKeyPath)
	p, _ := cspaillierSec.Decrypt(u, e, v, label)

	assert.Equal(t, m, p, "Camenisch-Shoup modified Paillier encryption/decryption does not work correctly")
}
