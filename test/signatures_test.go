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
	"log"
	"math/big"
	"testing"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/signatures"
)

func TestCL(t *testing.T) {
	numOfBlocks := 2
	cl := signatures.NewCL(numOfBlocks)
	n := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(160)), nil)
	//n, _ := new(big.Int).SetString("26959946667150639794667015087019630673557916260026308143510066298881", 10)

	m1 := common.GetRandomInt(n)
	m2 := common.GetRandomInt(n)
	var m_Ls []*big.Int
	m_Ls = append(m_Ls, m1)
	m_Ls = append(m_Ls, m2)

	signature, err := cl.Sign(m_Ls)
	if err != nil {
		log.Println(err)
	}

	pubKey := cl.GetPubKey()
	pubCL := signatures.NewPubCL(pubKey)
	ok, _ := pubCL.Verify(m_Ls, signature)
	log.Println(ok)
}
