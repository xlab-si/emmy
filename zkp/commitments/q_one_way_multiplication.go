package commitmentzkp

import (
	"github.com/xlab-si/emmy/crypto/common"
	"math/big"
)

// TODO: this is work in progress

// ProveCommitmentMultiplication demonstrates how, given commitments A, B, C, prover can
// prove that C = A * B. Note that commitments need to be based on q-one-way homomorphism
// (see RSABasedCommitter which is q-one-way homomorphism based).
func ProveCommitmentMultiplication(homomorphism func(*big.Int) *big.Int, homomorphismInv func(*big.Int) *big.Int,
	H common.Group, Q, Y,
	A, B, C, a, b, r, u, o *big.Int) bool {
	prover := NewQOneWayMultiplicationProver(homomorphism, homomorphismInv, H, Q, Y, A, B, C, a, b, r, u, o)
	verifier := NewQOneWayMultiplicationVerifier(homomorphism, H, Q, Y, A)

	m1 := prover.GetProofRandomData()
	verifier.SetProofRandomData(m1)

	challenge := verifier.GetChallenge()
	z, w1 := prover.GetProofData(challenge)
	proved := verifier.Verify(z, w1)

	return proved
}

type QOneWayMultiplicationProver struct {
	QOneWayHomomorphism func(*big.Int) *big.Int
	QOneWayHomomorphismInv func(*big.Int) *big.Int // works only for y^Q, takes y as input
	H 				 common.Group
	Q *big.Int
	Y *big.Int
	A *big.Int
	B *big.Int
	C *big.Int
	a *big.Int
	b *big.Int
	r *big.Int
	u *big.Int
	o *big.Int
	x *big.Int
	s1 *big.Int
}

func NewQOneWayMultiplicationProver(homomorphism func(*big.Int) *big.Int,
	homomorphismInv func(*big.Int) *big.Int,
	H common.Group, Q, Y, A, B, C, a, b, r, u, o *big.Int) *QOneWayMultiplicationProver {
	return &QOneWayMultiplicationProver{
		QOneWayHomomorphism: homomorphism,
		QOneWayHomomorphismInv: homomorphismInv,
		H: H,
		Q: Q,
		Y: Y,
		A: A,
		B: B,
		C: C,
		a: a,
		b: b,
		r: r,
		u: u,
		o: o,
	}
}

func (prover *QOneWayMultiplicationProver) GetProofRandomData() *big.Int {
	// m1 = y^x * f(s1) where x random from Z_q and s1 random from H
	x := common.GetRandomInt(prover.Q)
	s1 := prover.H.GetRandomElement()
	prover.x = x
	prover.s1 = s1
	t1 := prover.H.Exp(prover.Y, x)
	t2 := prover.QOneWayHomomorphism(s1)
	m1 := prover.H.Mul(t1, t2)
	return m1
}

func (prover *QOneWayMultiplicationProver) GetProofData(challenge *big.Int) (*big.Int, *big.Int) {
	// z = x + challenge * a mod Q
	z := prover.H.Mul(challenge, prover.a)
	z.Add(z, prover.x)
	zMod := new(big.Int).Mod(z, prover.Q)
	// choose i such that: z = x + ea + iq
	i := new(big.Int).Sub(z, zMod)	// choose i such that: z = x + ea + iq
	i.Div(i, prover.Q)

	// w1 := s1 * r^challenge * QOneWayHomomorphism^(-1)(y^(-iq))
	w1 := prover.H.Exp(prover.r, challenge)
	w1 = prover.H.Mul(prover.s1, w1)
	yToi := prover.H.Exp(prover.Y, i)
	yToiInv := prover.H.Inv(yToi) // y^(-i)
	pr := prover.QOneWayHomomorphismInv(yToiInv)
	w1 = prover.H.Mul(w1, pr)
	return z, w1
}

type QOneWayMultiplicationVerifier struct {
	QOneWayHomomorphism func(*big.Int) *big.Int
	H 				    common.Group
	Q					*big.Int
	Y					*big.Int
	A					*big.Int
	challenge           *big.Int
	m1           		*big.Int
}

func NewQOneWayMultiplicationVerifier(homomorphism func(*big.Int) *big.Int, H common.Group,
		Q, Y, A *big.Int) *QOneWayMultiplicationVerifier {
	return &QOneWayMultiplicationVerifier{
		QOneWayHomomorphism: homomorphism,
		H: H,
		Q: Q,
		Y: Y,
		A: A,
	}
}

func (verifier *QOneWayMultiplicationVerifier) SetProofRandomData(m1 *big.Int) {
	verifier.m1 = m1
}

func (verifier *QOneWayMultiplicationVerifier) GetChallenge() *big.Int {
	challenge := common.GetRandomInt(verifier.Q)
	verifier.challenge = challenge
	return challenge
}

func (verifier *QOneWayMultiplicationVerifier) Verify(z, w1 *big.Int) bool {
	// verifies whether y^z * f(w1) = m1 * A^challenge
	l1 := verifier.H.Exp(verifier.Y, z)
	l2 := verifier.QOneWayHomomorphism(w1)
	left := verifier.H.Mul(l1, l2)

	right := verifier.H.Exp(verifier.A, verifier.challenge)
	right = verifier.H.Mul(verifier.m1, right)

	if left.Cmp(right) == 0 {
		return true
	} else {
		return false
	}
}

