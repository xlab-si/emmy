package test

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"fmt"
)

func TestRSABasedCommitment(t *testing.T) {
	receiver, err := commitments.NewRSABasedCommitReceiver(1024)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Error when initializing RSABasedCommitReceiver")
	}

	committer, err := commitments.NewRSABasedCommitter(receiver.RSA.N, receiver.Q, receiver.Y)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Error when initializing RSABasedCommitter")
	}

	a := common.GetRandomInt(committer.Q)
	c, _ := committer.GetCommitMsg(a)

	receiver.SetCommitment(c)
	committedVal, r := committer.GetDecommitMsg()
	success := receiver.CheckDecommitment(r, committedVal)

	assert.Equal(t, true, success, "DLogEquality does not work correctly")
}

