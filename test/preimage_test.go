package test

import (
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/zkp/preimage"
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/xlab-si/emmy/crypto/common"
)

func TestFPreimage(t *testing.T) {
	rsa, _, err := commitments.GenerateRSABasedQOneWay(1024)
	if err != nil {
		t.Errorf("Error when initializing RSA")
	}
	v := common.GetZnInvertibleElement(rsa.N)
	H := common.NewZnGroup(rsa.N)
	prover := preimage.NewFPreimageProver(rsa.Exp, H, v)
	proofRandomData := prover.GetProofRandomData()

	u := rsa.Exp(v)
	verifier := preimage.NewFPreimageVerifier(rsa.Exp, H, rsa.E, u)
	verifier.SetProofRandomData(proofRandomData)
	challenge := verifier.GetChallenge()

	z := prover.GetProofData(challenge)
	proved := verifier.Verify(z)

	assert.Equal(t, true, proved, "FPreimage proof does not work correctly")
}

