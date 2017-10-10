package test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/commitments"
	"github.com/xlab-si/emmy/types"
	"math/big"
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

	assert.Equal(t, true, verified, "DLogEquality does not work correctly")
}

func TestCommitmentMultiplicationProof(t *testing.T) {
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
	b := common.GetRandomInt(committer.Q)
	A, err1 := committer.GetCommitMsg(a)
	_, r := committer.GetDecommitMsg()
	B, err2 := committer.GetCommitMsg(b)
	_, u := committer.GetDecommitMsg()
	// this management of commitments and decommitments is awkward,
	// see TODO in pedersen.go about refactoring commitment schemes API

	c := new(big.Int).Mul(a, b)
	c.Mod(c, committer.Q) // c = a * b mod Q
	C, o, tt := committer.GetCommitmentToMultiplication(a, b, u)
	if err1 != nil || err2 != nil {
		fmt.Println(err)
		t.Errorf("Error when computing commitments")
	}

	proved := commitmentzkp.ProveCommitmentMultiplication(committer.Homomorphism, receiver.HomomorphismInv,
		committer.H, committer.Q, committer.Y, types.NewTriple(A, B, C), types.NewPair(a, b),
		types.NewTriple(r, u, o), tt)

	assert.Equal(t, true, proved, "Commitments multiplication proof failed.")
}
