package test

import (
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/zkp/preimage"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFPreimage(t *testing.T) {
	homomorphism, _, H, Q, err := commitments.GenerateRSABasedQOneWay(1024)
	if err != nil {
		t.Errorf("Error when generating RSABasedQOneWay homomorphism")
	}
	v := H.GetRandomElement()
	u := homomorphism(v)

	proved := preimage.ProvePreimageKnowledge(homomorphism, H, Q, u, v)

	assert.Equal(t, true, proved, "FPreimage proof does not work correctly")
}

