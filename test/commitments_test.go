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
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/commitments"
	"testing"
)

func TestRSABasedCommitment(t *testing.T) {
	receiver, err := commitments.NewRSABasedCommitReceiver(1024)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Error when initializing RSABasedCommitReceiver")
	}

	committer, err := commitments.NewRSABasedCommitter(receiver.Homomorphism, receiver.HomomorphismInv,
		receiver.H, receiver.Q, receiver.Y)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Error when initializing RSABasedCommitter")
	}

	a := common.GetRandomInt(committer.Q)
	c, _ := committer.GetCommitMsg(a)

	receiver.SetCommitment(c)
	committedVal, r := committer.GetDecommitMsg()
	success := receiver.CheckDecommitment(r, committedVal)

	assert.Equal(t, true, success, "RSABasedCommitment does not work correctly")
}

func TestBitCommitmentProof(t *testing.T) {
	verified, err := commitmentzkp.ProveBitCommitment()
	if err != nil {
		fmt.Println(err)
		t.Errorf("Error in bit commitment proof.")
	}

	assert.Equal(t, true, verified, "Bit commitment does not work correctly")
}

func TestCommitmentMultiplicationProof(t *testing.T) {
	proved, err := commitmentzkp.ProveCommitmentMultiplication()
	if err != nil {
		fmt.Println(err)
		t.Errorf("Error in multiplication proof.")
	}

	assert.Equal(t, true, proved, "Commitments multiplication proof failed.")
}
