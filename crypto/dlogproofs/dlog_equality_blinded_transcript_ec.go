package dlogproofs

import (
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

// Verifies that the blinded transcript is valid. That means the knowledge of log_g1(t1), log_G2(T2)
// and log_g1(t1) = log_G2(T2). Note that G2 = g2^gamma, T2 = t2^gamma where gamma was chosen
// by verifier.
func VerifyBlindedTranscriptEC(transcript []*big.Int, curve dlog.Curve,
	g1, t1, G2, T2 *types.ECGroupElement) bool {
	dlog := dlog.NewECDLog(curve)
	// Transcript should be in the following form:
	// [alpha11, alpha12, beta11, beta12, hash(alpha11, alpha12, beta11, beta12), z+alpha]

	// check hash:
	hashNum := common.Hash(transcript[0], transcript[1], transcript[2], transcript[3])
	if hashNum.Cmp(transcript[4]) != 0 {
		return false
	}

	// We need to verify (note that c-beta = hash(alpha11, alpha12, beta11, beta12))
	// g1^(z+alpha) = (alpha11, alpha12) * t1^(c-beta)
	// G2^(z+alpha) = (beta11, beta12) * T2^(c-beta)
	left11, left12 := dlog.Exponentiate(g1.X, g1.Y, transcript[5])
	right11, right12 := dlog.Exponentiate(t1.X, t1.Y, transcript[4])
	right11, right12 = dlog.Multiply(transcript[0], transcript[1], right11, right12)

	left21, left22 := dlog.Exponentiate(G2.X, G2.Y, transcript[5])
	right21, right22 := dlog.Exponentiate(T2.X, T2.Y, transcript[4])
	right21, right22 = dlog.Multiply(transcript[2], transcript[3], right21, right22)

	if left11.Cmp(right11) == 0 && left12.Cmp(right12) == 0 &&
		left21.Cmp(right21) == 0 && left22.Cmp(right22) == 0 {
		return true
	} else {
		return false
	}
}

type ECDLogEqualityBTranscriptProver struct {
	DLog   *dlog.ECDLog
	r      *big.Int
	secret *big.Int
	g1     *types.ECGroupElement
	g2     *types.ECGroupElement
}

func NewECDLogEqualityBTranscriptProver(curve dlog.Curve) *ECDLogEqualityBTranscriptProver {
	dlog := dlog.NewECDLog(curve)
	prover := ECDLogEqualityBTranscriptProver{
		DLog: dlog,
	}
	return &prover
}

// Prove that you know dlog_g1(h1), dlog_g2(h2) and that dlog_g1(h1) = dlog_g2(h2).
func (prover *ECDLogEqualityBTranscriptProver) GetProofRandomData(secret *big.Int,
	g1, g2 *types.ECGroupElement) (*types.ECGroupElement, *types.ECGroupElement) {
	// Set the values that are needed before the protocol can be run.
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

func (prover *ECDLogEqualityBTranscriptProver) GetProofData(challenge *big.Int) *big.Int {
	// z = r + challenge * secret
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.DLog.GetOrderOfSubgroup())
	return z
}

type ECDLogEqualityBTranscriptVerifier struct {
	DLog       *dlog.ECDLog
	gamma      *big.Int
	challenge  *big.Int
	g1         *types.ECGroupElement
	g2         *types.ECGroupElement
	x1         *types.ECGroupElement
	x2         *types.ECGroupElement
	t1         *types.ECGroupElement
	t2         *types.ECGroupElement
	transcript []*big.Int
	alpha      *big.Int
}

func NewECDLogEqualityBTranscriptVerifier(curve dlog.Curve,
	gamma *big.Int) *ECDLogEqualityBTranscriptVerifier {
	dlog := dlog.NewECDLog(curve)
	if gamma == nil {
		gamma = common.GetRandomInt(dlog.GetOrderOfSubgroup())
	}
	verifier := ECDLogEqualityBTranscriptVerifier{
		DLog:  dlog,
		gamma: gamma,
	}

	return &verifier
}

func (verifier *ECDLogEqualityBTranscriptVerifier) GetChallenge(g1, g2, t1, t2, x1,
	x2 *types.ECGroupElement) *big.Int {
	// Set the values that are needed before the protocol can be run.
	// The protocol proves the knowledge of log_g1(t1), log_g2(t2) and
	// that log_g1(t1) = log_g2(t2).
	verifier.g1 = g1
	verifier.g2 = g2
	verifier.t1 = t1
	verifier.t2 = t2

	// Set the values g1^r1 and g2^r2.
	verifier.x1 = x1
	verifier.x2 = x2

	alpha := common.GetRandomInt(verifier.DLog.GetOrderOfSubgroup())
	beta := common.GetRandomInt(verifier.DLog.GetOrderOfSubgroup())

	// alpha1 = g1^r * g1^alpha * t1^beta
	// beta1 = (g2^r * g2^alpha * t2^beta)^gamma
	alpha11, alpha12 := verifier.DLog.Exponentiate(verifier.g1.X, verifier.g1.Y, alpha)
	alpha11, alpha12 = verifier.DLog.Multiply(verifier.x1.X, verifier.x1.Y, alpha11, alpha12)
	tmp1, tmp2 := verifier.DLog.Exponentiate(verifier.t1.X, verifier.t1.Y, beta)
	alpha11, alpha12 = verifier.DLog.Multiply(alpha11, alpha12, tmp1, tmp2)

	beta11, beta12 := verifier.DLog.Exponentiate(verifier.g2.X, verifier.g2.Y, alpha)
	beta11, beta12 = verifier.DLog.Multiply(verifier.x2.X, verifier.x2.Y, beta11, beta12)
	tmp1, tmp2 = verifier.DLog.Exponentiate(verifier.t2.X, verifier.t2.Y, beta)
	beta11, beta12 = verifier.DLog.Multiply(beta11, beta12, tmp1, tmp2)
	beta11, beta12 = verifier.DLog.Exponentiate(beta11, beta12, verifier.gamma)

	// c = hash(alpha1, beta) + beta mod q
	hashNum := common.Hash(alpha11, alpha12, beta11, beta12)
	challenge := new(big.Int).Add(hashNum, beta)
	challenge.Mod(challenge, verifier.DLog.OrderOfSubgroup)
	verifier.challenge = challenge

	var transcript []*big.Int
	transcript = append(transcript, alpha11)
	transcript = append(transcript, alpha12)
	transcript = append(transcript, beta11)
	transcript = append(transcript, beta12)
	transcript = append(transcript, hashNum)
	verifier.transcript = transcript
	verifier.alpha = alpha

	return challenge
}

// It receives z = r + secret * challenge.
//It returns true if g1^z = g1^r * (g1^secret) ^ challenge and g2^z = g2^r * (g2^secret) ^ challenge.
func (verifier *ECDLogEqualityBTranscriptVerifier) Verify(z *big.Int) (bool, []*big.Int,
	*types.ECGroupElement, *types.ECGroupElement) {
	left11, left12 := verifier.DLog.Exponentiate(verifier.g1.X, verifier.g1.Y, z)
	left21, left22 := verifier.DLog.Exponentiate(verifier.g2.X, verifier.g2.Y, z)

	r11, r12 := verifier.DLog.Exponentiate(verifier.t1.X, verifier.t1.Y, verifier.challenge)
	r21, r22 := verifier.DLog.Exponentiate(verifier.t2.X, verifier.t2.Y, verifier.challenge)
	right11, right12 := verifier.DLog.Multiply(r11, r12, verifier.x1.X, verifier.x1.Y)
	right21, right22 := verifier.DLog.Multiply(r21, r22, verifier.x2.X, verifier.x2.Y)

	// transcript [(alpha11, alpha12, beta11, beta12), hash(alpha11, alpha12, beta11, beta12), z+alpha]
	// however, we are actually returning:
	// [alpha11, alpha12, beta11, beta12, hash(alpha11, alpha12, beta11, beta12), z+alpha]
	z1 := new(big.Int).Add(z, verifier.alpha)
	verifier.transcript = append(verifier.transcript, z1)

	G21, G22 := verifier.DLog.Exponentiate(verifier.g2.X, verifier.g2.Y, verifier.gamma)
	T21, T22 := verifier.DLog.Exponentiate(verifier.t2.X, verifier.t2.Y, verifier.gamma)

	if left11.Cmp(right11) == 0 && left12.Cmp(right12) == 0 &&
		left21.Cmp(right21) == 0 && left22.Cmp(right22) == 0 {
		return true, verifier.transcript, types.NewECGroupElement(G21, G22),
			types.NewECGroupElement(T21, T22)
	} else {
		return false, nil, nil, nil
	}
}
