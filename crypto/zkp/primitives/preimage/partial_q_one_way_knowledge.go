package preimage

import (
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

// ProvePartialPreimageKnowledge demonstrates how prover can prove that he knows f^(-1)(u1) and
// the verifier does not know whether knowledge of f^(-1)(u1) or f^(-1)(u2) was proved.
// Note that PartialDLogKnowledge is a special case of PartialPreimageKnowledge.
func ProvePartialPreimageKnowledge(homomorphism func(*big.Int) *big.Int, H common.Group,
	q, v1, u1, u2 *big.Int) bool {
	prover := NewPartialPreimageProver(homomorphism, H, q, v1, u1, u2)
	verifier := NewPartialPreimageVerifier(homomorphism, H, q)

	pair1, pair2 := prover.GetProofRandomData()

	verifier.SetProofRandomData(pair1, pair2)
	challenge := verifier.GetChallenge()

	c1, z1, c2, z2 := prover.GetProofData(challenge)
	verified := verifier.Verify(c1, z1, c2, z2)
	return verified
}

type PartialPreimageProver struct {
	QOneWayHomomorphism func(*big.Int) *big.Int
	H                   common.Group
	Q                   *big.Int
	v1                  *big.Int
	u1                  *big.Int
	u2                  *big.Int
	r1                  *big.Int
	c2                  *big.Int
	z2                  *big.Int
	ord                 int
}

func NewPartialPreimageProver(homomorphism func(*big.Int) *big.Int, H common.Group,
	q, v1, u1, u2 *big.Int) *PartialPreimageProver {
	return &PartialPreimageProver{
		QOneWayHomomorphism: homomorphism,
		H:                   H,
		Q:                   q,
		v1:                  v1,
		u1:                  u1,
		u2:                  u2,
	}
}

// GetProofRandomData returns QOneWayHomomorphism(r1) and QOneWayHomomorphism(r2)/(u2^c2)
// in random order and where r1 and r2 are random from H.
func (prover *PartialPreimageProver) GetProofRandomData() (*types.Pair, *types.Pair) {
	r1 := prover.H.GetRandomElement()
	c2 := common.GetRandomInt(prover.Q)
	z2 := prover.H.GetRandomElement()
	prover.r1 = r1
	prover.c2 = c2
	prover.z2 = z2
	x1 := prover.QOneWayHomomorphism(r1)
	x2 := prover.QOneWayHomomorphism(z2)
	u2ToC2 := prover.H.Exp(prover.u2, c2)
	u2ToC2Inv := prover.H.Inv(u2ToC2)
	x2 = prover.H.Mul(x2, u2ToC2Inv)

	// we need to make sure that the order does not reveal which secret we do know:
	ord := common.GetRandomInt(big.NewInt(2))
	pair1 := types.NewPair(x1, prover.u1)
	pair2 := types.NewPair(x2, prover.u2)

	if ord.Cmp(big.NewInt(0)) == 0 {
		prover.ord = 0
		return pair1, pair2
	} else {
		prover.ord = 1
		return pair2, pair1
	}
}

func (prover *PartialPreimageProver) GetProofData(challenge *big.Int) (*big.Int, *big.Int,
	*big.Int, *big.Int) {
	c1 := new(big.Int).Xor(prover.c2, challenge)
	// z1 = r*v^e
	z1 := prover.H.Exp(prover.v1, c1)
	z1 = prover.H.Mul(prover.r1, z1)

	if prover.ord == 0 {
		return c1, z1, prover.c2, prover.z2
	} else {
		return prover.c2, prover.z2, c1, z1
	}
}

type PartialPreimageVerifier struct {
	QOneWayHomomorphism func(*big.Int) *big.Int
	H                   common.Group
	Q                   *big.Int
	pair1               *types.Pair
	pair2               *types.Pair
	challenge           *big.Int
}

func NewPartialPreimageVerifier(homomorphism func(*big.Int) *big.Int,
	H common.Group, q *big.Int) *PartialPreimageVerifier {
	return &PartialPreimageVerifier{
		QOneWayHomomorphism: homomorphism,
		H:                   H,
		Q:                   q,
	}
}

func (verifier *PartialPreimageVerifier) SetProofRandomData(pair1, pair2 *types.Pair) {
	verifier.pair1 = pair1
	verifier.pair2 = pair2
}

func (verifier *PartialPreimageVerifier) GetChallenge() *big.Int {
	challenge := common.GetRandomInt(verifier.Q)
	verifier.challenge = challenge
	return challenge
}

func (verifier *PartialPreimageVerifier) verifyPair(pair *types.Pair,
	challenge, z *big.Int) bool {
	left := verifier.QOneWayHomomorphism(z)
	r1 := verifier.H.Exp(pair.B, challenge)
	right := verifier.H.Mul(r1, pair.A)
	return left.Cmp(right) == 0
}

func (verifier *PartialPreimageVerifier) Verify(c1, z1, c2, z2 *big.Int) bool {
	c := new(big.Int).Xor(c1, c2)
	if c.Cmp(verifier.challenge) != 0 {
		return false
	}

	verified1 := verifier.verifyPair(verifier.pair1, c1, z1)
	verified2 := verifier.verifyPair(verifier.pair2, c2, z2)
	return verified1 && verified2
}
