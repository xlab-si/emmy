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

package commitments

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/common"
)

func TestDamgardFujisaki(t *testing.T) {
	safePrimeBitLength := 1024
	receiver, err := NewDamgardFujisakiReceiver(safePrimeBitLength)
	if err != nil {
		t.Errorf("Error in NewDamgardFujisakiReceiver: %v", err)
	}

	committer := NewDamgardFujisakiCommitter(receiver.QRSpecialRSA.N, receiver.H, receiver.G)
	a := common.GetRandomInt(receiver.QRSpecialRSA.N)
	c, err := committer.GetCommitMsg(a)
	if err != nil {
		t.Errorf("Error in GetCommitMsg: %v", err)
	}

	receiver.SetCommitment(c)
	committedVal, r := committer.GetDecommitMsg()
	success := receiver.CheckDecommitment(r, committedVal)

	assert.Equal(t, true, success, "DamgardFujisaki commitment failed.")
}
