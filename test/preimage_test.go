package test

import (
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/preimage"
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
