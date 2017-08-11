package dlogproofs

import (
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	"math/big"
)

func RunDLogEquality(secret, g1, g2, t1, t2 *big.Int, dlog *dlog.ZpDLog) bool {
	// no wrappers at the moment, because messages handling will be refactored
	eProver := NewDLogEqualityProver(dlog)
	eVerifier := NewDLogEqualityVerifier(dlog)

	x1, x2 := eProver.GetProofRandomData(secret, g1, g2)

	challenge := eVerifier.GetChallenge(g1, g2, t1, t2, x1, x2)
	z := eProver.GetProofData(challenge)
	verified := eVerifier.Verify(z)
	return verified
}

type DLogEqualityProver struct {
	DLog   *dlog.ZpDLog
	r      *big.Int
	secret *big.Int
	g1     *big.Int
	g2     *big.Int
}

func NewDLogEqualityProver(dlog *dlog.ZpDLog) *DLogEqualityProver {
	prover := DLogEqualityProver{
		DLog: dlog,
	}

	return &prover
}

func (prover *DLogEqualityProver) GetProofRandomData(secret, g1, g2 *big.Int) (*big.Int, *big.Int) {
	// Sets the values that are needed before the protocol can be run.
	// The protocol proves the knowledge of log_g1(t1), log_g2(t2) and
	// that log_g1(t1) = log_g2(t2).
	prover.secret = secret
	prover.g1 = g1
	prover.g2 = g2

	r := common.GetRandomInt(prover.DLog.GetOrderOfSubgroup())
	prover.r = r
	x1, _ := prover.DLog.Exponentiate(prover.g1, r)
	x2, _ := prover.DLog.Exponentiate(prover.g2, r)
	return x1, x2
}

func (prover *DLogEqualityProver) GetProofData(challenge *big.Int) *big.Int {
	// z = r + challenge * secret
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.DLog.GetOrderOfSubgroup())
	return z
}

type DLogEqualityVerifier struct {
	DLog      *dlog.ZpDLog
	challenge *big.Int
	g1        *big.Int
	g2        *big.Int
	x1        *big.Int
	x2        *big.Int
	t1        *big.Int
	t2        *big.Int
}

func NewDLogEqualityVerifier(dlog *dlog.ZpDLog) *DLogEqualityVerifier {
	verifier := DLogEqualityVerifier{
		DLog: dlog,
	}

	return &verifier
}

func (verifier *DLogEqualityVerifier) GetChallenge(g1, g2, t1, t2, x1, x2 *big.Int) *big.Int {
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
func (verifier *DLogEqualityVerifier) Verify(z *big.Int) bool {
	left1, _ := verifier.DLog.Exponentiate(verifier.g1, z)
	left2, _ := verifier.DLog.Exponentiate(verifier.g2, z)

	r11, _ := verifier.DLog.Exponentiate(verifier.t1, verifier.challenge)
	r12, _ := verifier.DLog.Exponentiate(verifier.t2, verifier.challenge)
	right1, _ := verifier.DLog.Multiply(r11, verifier.x1)
	right2, _ := verifier.DLog.Multiply(r12, verifier.x2)

	if left1.Cmp(right1) == 0 && left2.Cmp(right2) == 0 {
		return true
	} else {
		return false
	}
}
