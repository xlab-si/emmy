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

package encryption

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/common"
)

func TestPaillier(t *testing.T) {
	paillier := NewPaillier(1024)
	pubKey := paillier.GetPubKey()

	m := common.GetRandomInt(big.NewInt(123412341234123))
	pubPaillier := NewPubPaillier(pubKey)
	c, _ := pubPaillier.Encrypt(m)
	p, _ := paillier.Decrypt(c)

	assert.Equal(t, m, p, "Paillier encryption/decryption does not work correctly")
}
