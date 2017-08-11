package dlogproofs

import (
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

func RunECDLogEquality(secret *big.Int, g1, g2, t1, t2 *types.ECGroupElement,
	curve dlog.Curve) bool {
	eProver := NewECDLogEqualityProver(curve)
	eVerifier := NewECDLogEqualityVerifier(curve)

	x1, x2 := eProver.GetProofRandomData(secret, g1, g2)

	challenge := eVerifier.GetChallenge(g1, g2, t1, t2, x1, x2)
	z := eProver.GetProofData(challenge)
	verified := eVerifier.Verify(z)
	return verified
}

type ECDLogEqualityProver struct {
	DLog   *dlog.ECDLog
	r      *big.Int
	secret *big.Int
	g1     *types.ECGroupElement
	g2     *types.ECGroupElement
}

func NewECDLogEqualityProver(curve dlog.Curve) *ECDLogEqualityProver {
	dlog := dlog.NewECDLog(curve)
	prover := ECDLogEqualityProver{
		DLog: dlog,
	}

	return &prover
}

func (prover *ECDLogEqualityProver) GetProofRandomData(secret *big.Int,
	g1, g2 *types.ECGroupElement) (*types.ECGroupElement, *types.ECGroupElement) {
	// Sets the values that are needed before the protocol can be run.
	// The protocol proves the knowledge of log_g1(t1), log_g2(t2) and
	// that log_g1(t1) = log_g2(t2).
	prover.secret = secret
	prover.g1 = g1
	prover.g2 = g2

	r := common.GetRandomInt(prover.DLog.GetOrderOfSubgroup())
	prover.r = r
	x1, y1 := prover.DLog.Exponentiate(prover.g1.X, prover.g1.Y, r)
	x2, y2 := prover.DLog.Exponentiate(prover.g2.X, prover.g2.Y, r)
	return types.NewECGroupElement(x1, y1), types.NewECGroupElement(x2, y2)
}

func (prover *ECDLogEqualityProver) GetProofData(challenge *big.Int) *big.Int {
	// z = r + challenge * secret
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.DLog.GetOrderOfSubgroup())
	return z
}

type ECDLogEqualityVerifier struct {
	DLog      *dlog.ECDLog
	challenge *big.Int
	g1        *types.ECGroupElement
	g2        *types.ECGroupElement
	x1        *types.ECGroupElement
	x2        *types.ECGroupElement
	t1        *types.ECGroupElement
	t2        *types.ECGroupElement
}

func NewECDLogEqualityVerifier(curve dlog.Curve) *ECDLogEqualityVerifier {
	dlog := dlog.NewECDLog(curve)
	verifier := ECDLogEqualityVerifier{
		DLog: dlog,
	}

	return &verifier
}

func (verifier *ECDLogEqualityVerifier) GetChallenge(g1, g2, t1, t2, x1,
	x2 *types.ECGroupElement) *big.Int {
	// Set the values that are needed before the protocol can be run.
	// The protocol proves the knowledge of log_g1(t1), log_g2(t2) and
	// that log_g1(t1) = log_g2(t2).
	verifier.g1 = g1
	verifier.g2 = g2
	verifier.t1 = t1
	verifier.t2 = t2

	// Sets the values g1^r1 and g2^r2.
	verifier.x1 = x1
	verifier.x2 = x2

	challenge := common.GetRandomInt(verifier.DLog.GetOrderOfSubgroup())
	verifier.challenge = challenge
	return challenge
}

// It receives z = r + secret * challenge.
//It returns true if g1^z = g1^r * (g1^secret) ^ challenge and g2^z = g2^r * (g2^secret) ^ challenge.
func (verifier *ECDLogEqualityVerifier) Verify(z *big.Int) bool {
	left11, left12 := verifier.DLog.Exponentiate(verifier.g1.X, verifier.g1.Y, z)
	left21, left22 := verifier.DLog.Exponentiate(verifier.g2.X, verifier.g2.Y, z)

	r11, r12 := verifier.DLog.Exponentiate(verifier.t1.X, verifier.t1.Y, verifier.challenge)
	r21, r22 := verifier.DLog.Exponentiate(verifier.t2.X, verifier.t2.Y, verifier.challenge)
	right11, right12 := verifier.DLog.Multiply(r11, r12, verifier.x1.X, verifier.x1.Y)
	right21, right22 := verifier.DLog.Multiply(r21, r22, verifier.x2.X, verifier.x2.Y)

	if left11.Cmp(right11) == 0 && left12.Cmp(right12) == 0 &&
		left21.Cmp(right21) == 0 && left22.Cmp(right22) == 0 {
		return true
	} else {
		return false
	}
}
