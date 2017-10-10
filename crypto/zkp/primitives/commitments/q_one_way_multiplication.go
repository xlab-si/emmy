package commitmentzkp

import (
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

// ProveCommitmentMultiplication demonstrates how, given commitments A, B, C, prover can
// prove that C = A * B. Note that commitments need to be based on q-one-way homomorphism
// (see RSABasedCommitter which is q-one-way homomorphism based).
func ProveCommitmentMultiplication(homomorphism func(*big.Int) *big.Int, homomorphismInv func(*big.Int) *big.Int,
	H common.Group, Q *big.Int, Y *big.Int, commitments *types.Triple, committedValues *types.Pair,
	randomValues *types.Triple, t *big.Int) bool {
	prover := NewQOneWayMultiplicationProver(homomorphism, homomorphismInv, H, Q, Y,
		commitments, committedValues, randomValues, t)
	verifier := NewQOneWayMultiplicationVerifier(homomorphism, H, Q, Y, commitments)

	m1, m2, m3 := prover.GetProofRandomData()
	verifier.SetProofRandomData(m1, m2, m3)

	challenge := verifier.GetChallenge()
	z1, w1, w2, z2, w3 := prover.GetProofData(challenge)
	proved := verifier.Verify(z1, w1, w2, z2, w3)

	return proved
}

type QOneWayMultiplicationProver struct {
	QOneWayHomomorphism    func(*big.Int) *big.Int
	QOneWayHomomorphismInv func(*big.Int) *big.Int // works only for y^Q, takes y as input
	H                      common.Group
	Q                      *big.Int
	Y                      *big.Int
	A                      *big.Int // commitments to a
	B                      *big.Int // commitment to b
	C                      *big.Int // commitment to c = a * b mod Q
	a                      *big.Int
	b                      *big.Int
	r                      *big.Int // r is random factor in A
	u                      *big.Int // u is random factor in B
	o                      *big.Int // o is random factor in C
	t                      *big.Int // t is such that: C = B^a * f(t)
	x                      *big.Int // for protocol 1
	s1                     *big.Int // for protocol 1
	s2                     *big.Int // for protocol 1
	d                      *big.Int // for protocol 2
	s                      *big.Int // for protocol 2
	// proof consists of two protocols: The first is intended to verify
	// that A, C have the correct form, while the second verifies that the prover can open B.
}

func NewQOneWayMultiplicationProver(homomorphism func(*big.Int) *big.Int,
	homomorphismInv func(*big.Int) *big.Int,
	H common.Group, Q, Y *big.Int, commitments *types.Triple, committedValues *types.Pair,
	randomValues *types.Triple, t *big.Int) *QOneWayMultiplicationProver {
	return &QOneWayMultiplicationProver{
		QOneWayHomomorphism:    homomorphism,
		QOneWayHomomorphismInv: homomorphismInv,
		H: H,
		Q: Q,
		Y: Y,
		A: commitments.A,
		B: commitments.B,
		C: commitments.C,
		a: committedValues.A,
		b: committedValues.B,
		r: randomValues.A,
		u: randomValues.B,
		o: randomValues.C,
		t: t,
	}
}

func (prover *QOneWayMultiplicationProver) GetProofRandomData() (*big.Int, *big.Int, *big.Int) {
	// m1 = Y^x * f(s1) where x random from Z_q and s1 random from H
	x := common.GetRandomInt(prover.Q)
	s1 := prover.H.GetRandomElement()
	s2 := prover.H.GetRandomElement()
	prover.x = x
	prover.s1 = s1
	prover.s2 = s2
	m1 := helper(prover.QOneWayHomomorphism, prover.H, prover.Y, x, s1)
	// m2 = B^x * f(s2)
	m2 := helper(prover.QOneWayHomomorphism, prover.H, prover.B, x, s2)

	// m3 = Y^d * f(s)
	d := common.GetRandomInt(prover.Q)
	s := prover.H.GetRandomElement()
	prover.d = d
	prover.s = s
	m3 := helper(prover.QOneWayHomomorphism, prover.H, prover.Y, d, s)

	return m1, m2, m3
}

func (prover *QOneWayMultiplicationProver) GetProofData(challenge *big.Int) (*big.Int, *big.Int,
	*big.Int, *big.Int, *big.Int) {
	// protocol 1 (verifies that A and C have the correct form):

	// z1 = x + challenge * a mod Q
	z1 := new(big.Int).Mul(challenge, prover.a)
	z1.Add(z1, prover.x)
	z1Mod := new(big.Int).Mod(z1, prover.Q)
	// choose i such that: z = x + challenge*a + i*Q
	i := new(big.Int).Sub(z1, z1Mod)
	i.Div(i, prover.Q)

	// w1 = s1 * r^challenge * QOneWayHomomorphism^(-1)(y^(i*q))
	w1 := prover.H.Exp(prover.r, challenge)
	w1 = prover.H.Mul(prover.s1, w1)
	yToi := prover.H.Exp(prover.Y, i)
	// there is a mistake in a paper - f^(-1)(y^(-i*q)) is used instead of f^(-1)(y^(i*q)):
	pr := prover.QOneWayHomomorphismInv(yToi)
	w1 = prover.H.Mul(w1, pr)

	w2 := prover.H.Exp(prover.t, challenge)
	w2 = prover.H.Mul(prover.s2, w2)
	BToi := prover.H.Exp(prover.B, i)
	// there is a mistake in a paper - f^(-1)(B^(-i*q)) is used instead of f^(-1)(B^(i*q)):
	pr = prover.QOneWayHomomorphismInv(BToi)
	w2 = prover.H.Mul(w2, pr)

	// protocol 2 (verifies that the prover can open B):

	// z2 = d + challenge * b mod Q
	z2 := new(big.Int).Mul(challenge, prover.b)
	z2.Add(z2, prover.d)
	z2Mod := new(big.Int).Mod(z2, prover.Q)
	// choose j such that: z2 = d + challenge*b + j*Q
	j := new(big.Int).Sub(z2, z2Mod)
	j.Div(j, prover.Q)

	// w3 = s * u^challenge * QOneWayHomomorphism^(-1)(y^(j*q))
	w3 := prover.H.Exp(prover.u, challenge)
	w3 = prover.H.Mul(prover.s, w3)
	yToj := prover.H.Exp(prover.Y, j)
	pr = prover.QOneWayHomomorphismInv(yToj)
	w3 = prover.H.Mul(w3, pr)

	return z1Mod, w1, w2, z2Mod, w3
}

type QOneWayMultiplicationVerifier struct {
	QOneWayHomomorphism func(*big.Int) *big.Int
	H                   common.Group
	Q                   *big.Int
	Y                   *big.Int
	A                   *big.Int
	B                   *big.Int
	C                   *big.Int
	challenge           *big.Int
	m1                  *big.Int
	m2                  *big.Int
	m3                  *big.Int
}

func NewQOneWayMultiplicationVerifier(homomorphism func(*big.Int) *big.Int, H common.Group,
	Q, Y *big.Int, commitments *types.Triple) *QOneWayMultiplicationVerifier {
	return &QOneWayMultiplicationVerifier{
		QOneWayHomomorphism: homomorphism,
		H:                   H,
		Q:                   Q,
		Y:                   Y,
		A:                   commitments.A,
		B:                   commitments.B,
		C:                   commitments.C,
	}
}

func (verifier *QOneWayMultiplicationVerifier) SetProofRandomData(m1, m2, m3 *big.Int) {
	verifier.m1 = m1
	verifier.m2 = m2
	verifier.m3 = m3
}

func (verifier *QOneWayMultiplicationVerifier) GetChallenge() *big.Int {
	challenge := common.GetRandomInt(verifier.Q)
	verifier.challenge = challenge
	return challenge
}

func (verifier *QOneWayMultiplicationVerifier) Verify(z1, w1, w2, z2, w3 *big.Int) bool {
	// verifies whether Y^z * f(w1) = m1 * A^challenge and
	// B^z * f(w2) = m2 * C^challenge
	left1 := helper(verifier.QOneWayHomomorphism, verifier.H, verifier.Y, z1, w1)
	right1 := verifier.H.Exp(verifier.A, verifier.challenge)
	right1 = verifier.H.Mul(verifier.m1, right1)

	left2 := helper(verifier.QOneWayHomomorphism, verifier.H, verifier.B, z1, w2)
	right2 := verifier.H.Exp(verifier.C, verifier.challenge)
	right2 = verifier.H.Mul(verifier.m2, right2)

	// verifies whether Y^z2 * f(w3) = m3 * B^challenge
	left3 := helper(verifier.QOneWayHomomorphism, verifier.H, verifier.Y, z2, w3)
	right3 := verifier.H.Exp(verifier.B, verifier.challenge)
	right3 = verifier.H.Mul(verifier.m3, right3)

	return left1.Cmp(right1) == 0 && left2.Cmp(right2) == 0 &&
		left3.Cmp(right3) == 0
}

// Returns x^y * f(s) computed in group H.
func helper(f func(*big.Int) *big.Int, H common.Group, x, y, s *big.Int) *big.Int {
	t1 := H.Exp(x, y)
	t2 := f(s)
	return H.Mul(t1, t2)
}
