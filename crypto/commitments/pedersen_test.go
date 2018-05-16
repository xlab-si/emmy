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

// TestPedersen demonstrates how a value can be committed and later opened (decommitted) using Pedersen committer.
func TestPedersen(t *testing.T) {
	receiver, err := NewPedersenReceiver(256)
	if err != nil {
		t.Errorf("Error in NewPedersenReceiver: %v", err)
	}

	committer := NewPedersenCommitter(receiver.Params)

	a := common.GetRandomInt(committer.Params.Group.Q)
	c, err := committer.GetCommitMsg(a)
	if err != nil {
		t.Errorf("Error in GetCommitMsg: %v", err)
	}

	receiver.SetCommitment(c)
	committedVal, r := committer.GetDecommitMsg()
	success := receiver.CheckDecommitment(r, committedVal)

	assert.Equal(t, true, success, "Pedersen commitment failed.")
}
