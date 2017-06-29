package dlogproofs

import (
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"math/big"
)

// Verifies that the blinded transcript is valid. That means the knowledge of log_g1(t1), log_G2(T2)
// and log_g1(t1) = log_G2(T2). Note that G2 = g2^gamma, T2 = t2^gamma where gamma was chosen
// by verifier.
func VerifyBlindedTranscript(transcript []*big.Int, dlog *dlog.ZpDLog, g1, t1, G2, T2 *big.Int) bool {
	// Transcript should be in the following form: [alpha1, beta1, hash(alpha1, beta1), z+alpha]

	// check hash:
	hashNum := common.Hash(transcript[0], transcript[1])
	if hashNum.Cmp(transcript[2]) != 0 {
		return false
	}

	// We need to verify (note that c-beta = hash(alpha1, beta1))
	// g1^(z+alpha) = alpha1 * t1^(c-beta)
	// G2^(z+alpha) = beta1 * T2^(c-beta)
	left1, _ := dlog.Exponentiate(g1, transcript[3])
	right1, _ := dlog.Exponentiate(t1, transcript[2])
	right1, _ = dlog.Multiply(transcript[0], right1)

	left2, _ := dlog.Exponentiate(G2, transcript[3])
	right2, _ := dlog.Exponentiate(T2, transcript[2])
	right2, _ = dlog.Multiply(transcript[1], right2)

	if left1.Cmp(right1) == 0 && left2.Cmp(right2) == 0 {
		return true
	} else {
		return false
	}
}

type DLogEqualityBTranscriptProver struct {
	DLog   *dlog.ZpDLog
	r      *big.Int
	secret *big.Int
	g1     *big.Int
	g2     *big.Int
}

func NewDLogEqualityBTranscriptProver(dlog *dlog.ZpDLog) *DLogEqualityBTranscriptProver {
	prover := DLogEqualityBTranscriptProver{
		DLog: dlog,
	}
	return &prover
}

// Prove that you know dlog_g1(h1), dlog_g2(h2) and that dlog_g1(h1) = dlog_g2(h2).
func (prover *DLogEqualityBTranscriptProver) GetProofRandomData(secret, g1, g2 *big.Int) (*big.Int,
	*big.Int) {
	// Set the values that are needed before the protocol can be run.
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

func (prover *DLogEqualityBTranscriptProver) GetProofData(challenge *big.Int) *big.Int {
	// z = r + challenge * secret
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.DLog.GetOrderOfSubgroup())
	return z
}

type DLogEqualityBTranscriptVerifier struct {
	DLog       *dlog.ZpDLog
	gamma      *big.Int
	challenge  *big.Int
	g1         *big.Int
	g2         *big.Int
	x1         *big.Int
	x2         *big.Int
	t1         *big.Int
	t2         *big.Int
	transcript []*big.Int
	alpha      *big.Int
}

func NewDLogEqualityBTranscriptVerifier(dlog *dlog.ZpDLog,
	gamma *big.Int) *DLogEqualityBTranscriptVerifier {
	if gamma == nil {
		gamma = common.GetRandomInt(dlog.GetOrderOfSubgroup())
	}
	verifier := DLogEqualityBTranscriptVerifier{
		DLog:  dlog,
		gamma: gamma,
	}

	return &verifier
}

func (verifier *DLogEqualityBTranscriptVerifier) GetChallenge(g1, g2, t1, t2, x1, x2 *big.Int) *big.Int {
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
	alpha1, _ := verifier.DLog.Exponentiate(verifier.g1, alpha)
	alpha1, _ = verifier.DLog.Multiply(verifier.x1, alpha1)
	tmp, _ := verifier.DLog.Exponentiate(verifier.t1, beta)
	alpha1, _ = verifier.DLog.Multiply(alpha1, tmp)

	beta1, _ := verifier.DLog.Exponentiate(verifier.g2, alpha)
	beta1, _ = verifier.DLog.Multiply(verifier.x2, beta1)
	tmp, _ = verifier.DLog.Exponentiate(verifier.t2, beta)
	beta1, _ = verifier.DLog.Multiply(beta1, tmp)
	beta1, _ = verifier.DLog.Exponentiate(beta1, verifier.gamma)

	// c = hash(alpha1, beta) + beta mod q
	hashNum := common.Hash(alpha1, beta1)
	challenge := new(big.Int).Add(hashNum, beta)
	challenge.Mod(challenge, verifier.DLog.OrderOfSubgroup)
	verifier.challenge = challenge

	var transcript []*big.Int
	transcript = append(transcript, alpha1)
	transcript = append(transcript, beta1)
	transcript = append(transcript, hashNum)
	verifier.transcript = transcript
	verifier.alpha = alpha

	return challenge
}

// It receives z = r + secret * challenge.
//It returns true if g1^z = g1^r * (g1^secret) ^ challenge and g2^z = g2^r * (g2^secret) ^ challenge.
func (verifier *DLogEqualityBTranscriptVerifier) Verify(z *big.Int) (bool, []*big.Int,
	*big.Int, *big.Int) {
	left1, _ := verifier.DLog.Exponentiate(verifier.g1, z)
	left2, _ := verifier.DLog.Exponentiate(verifier.g2, z)

	r11, _ := verifier.DLog.Exponentiate(verifier.t1, verifier.challenge)
	r12, _ := verifier.DLog.Exponentiate(verifier.t2, verifier.challenge)
	right1, _ := verifier.DLog.Multiply(r11, verifier.x1)
	right2, _ := verifier.DLog.Multiply(r12, verifier.x2)

	// transcript [(alpha1, beta1), hash(alpha1, beta1), z+alpha]
	// however, we are actually returning [alpha1, beta1, hash(alpha1, beta1), z+alpha]
	z1 := new(big.Int).Add(z, verifier.alpha)
	verifier.transcript = append(verifier.transcript, z1)

	G2, _ := verifier.DLog.Exponentiate(verifier.g2, verifier.gamma)
	T2, _ := verifier.DLog.Exponentiate(verifier.t2, verifier.gamma)

	if left1.Cmp(right1) == 0 && left2.Cmp(right2) == 0 {
		return true, verifier.transcript, G2, T2
	} else {
		return false, nil, nil, nil
	}
}
