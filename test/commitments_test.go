package test

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"fmt"
	"github.com/xlab-si/emmy/zkp/commitments"
)

func TestRSABasedCommitment(t *testing.T) {
	receiver, err := commitments.NewRSABasedCommitReceiver(1024)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Error when initializing RSABasedCommitReceiver")
	}

	committer, err := commitments.NewRSABasedCommitter(receiver.RSA.N, receiver.RSA.E, receiver.Y)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Error when initializing RSABasedCommitter")
	}

	a := common.GetRandomInt(committer.RSA.E)
	c, _ := committer.GetCommitMsg(a)

	receiver.SetCommitment(c)
	committedVal, r := committer.GetDecommitMsg()
	success := receiver.CheckDecommitment(r, committedVal)

	assert.Equal(t, true, success, "RSABasedCommitment does not work correctly")
}

func TestBitCommitmentProof(t *testing.T) {
	verified, err := commitments.ProveBitCommitment()
	if err != nil {
		fmt.Println(err)
		t.Errorf("Error in bit commitment proof.")
	}

	assert.Equal(t, true, verified, "DLogEquality does not work correctly")
}

func TestCommitmentMultiplicationProof(t *testing.T) {
	receiver, err := commitments.NewRSABasedCommitReceiver(1024)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Error when initializing RSABasedCommitReceiver")
	}

	committer, err := commitments.NewRSABasedCommitter(receiver.RSA.N, receiver.RSA.E, receiver.Y)
	if err != nil {
		fmt.Println(err)
		t.Errorf("Error when initializing RSABasedCommitter")
	}
	H := common.NewZnGroup(committer.RSA.N)

	a := common.GetRandomInt(committer.RSA.E)
	b := common.GetRandomInt(committer.RSA.E)
	A, err1 := committer.GetCommitMsg(a)
	_, r := committer.GetDecommitMsg()
	B, err2 := committer.GetCommitMsg(b)
	_, u := committer.GetDecommitMsg()
	// this management of commitments and decommitments is awkward,
	// see TODO in pedersen.go about refactoring commitment schemes API

	c := H.Mul(a, b)
	C, err3 := committer.GetCommitMsg(c)
	_, o := committer.GetDecommitMsg()
	if err1 != nil || err2 != nil || err3 != nil {
		fmt.Println(err)
		t.Errorf("Error when computing commitments")
	}

	//C, o, tt := committer.GetCommitmentToMultiplication(a, b, u)

	proved := commitmentzkp.ProveCommitmentMultiplication(committer.RSA.Exp, receiver.HomomorphismInv,
		H, committer.RSA.E, committer.Y, A, B, C, a, b, r, u, o)

	assert.Equal(t, true, proved, "Commitments multiplication proof failed.")
}

