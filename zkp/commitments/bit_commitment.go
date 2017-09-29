package commitmentzkp

import (
	"math/big"
	"github.com/xlab-si/emmy/zkp/preimage"
	"github.com/xlab-si/emmy/crypto/commitments"
)

// ProveBitCommitment demonstrates how committer can prove that a commitment contains
// 0 or 1. This is achieved by using PartialPreimageProver.
func ProveBitCommitment() (bool, error) {
	receiver, err := commitments.NewRSABasedCommitReceiver(1024)
	if err != nil {
		return false, err
	}

	committer, err := commitments.NewRSABasedCommitter(receiver.Homomorphism, receiver.HomomorphismInv,
		receiver.H, receiver.Q, receiver.Y)
	if err != nil {
		return false, err
	}

	u1, _ := committer.GetCommitMsg(big.NewInt(0))
	// commitment contains 0: u1 = commitment(0)
	// if we would like to have a commitment that contains 1, we
	// need to use u1 = Y^(-1) * c where c is committer.GetCommitMsg(big.NewInt(1))
	_, v1 := committer.GetDecommitMsg() // v1 is a random r used in commitment: c = Y^a * r^q mod N

	// receiver.RSA.E is Q
	u2 := committer.H.GetRandomElement()

	prover := preimage.NewPartialPreimageProver(committer.Homomorphism, committer.H,
		committer.Q, v1, u1, u2)
	verifier := preimage.NewPartialPreimageVerifier(receiver.Homomorphism, receiver.H,
		receiver.Q)

	pair1, pair2 := prover.GetProofRandomData()

	verifier.SetProofRandomData(pair1, pair2)
	challenge := verifier.GetChallenge()

	c1, z1, c2, z2 := prover.GetProofData(challenge)
	verified := verifier.Verify(c1, z1, c2, z2)

	return verified, nil
}
