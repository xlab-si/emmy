package qrproofs

// Zero-knowledge proof	of quadratic residousity (implemented for historical reasons)

import (
	"errors"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	"math/big"
)

func ExecuteProtocol(y1 *big.Int, dlog *dlog.ZpDLog) bool {
	y, _ := dlog.Multiply(y1, y1)
	prover := NewQRProver(dlog, y1)
	verifier := NewQRVerifier(y, dlog)
	m := dlog.P.BitLen()

	for i := 0; i < m; i++ {
		x := prover.GetProofRandomData()
		c := verifier.GetChallenge(x)

		z, _ := prover.GetProofData(c)

		proved := verifier.Verify(z)
		if !proved {
			return false
		}
	}
	return true
}

type QRProver struct {
	DLog *dlog.ZpDLog
	Y    *big.Int
	y1   *big.Int
	r    *big.Int
}

func NewQRProver(dlog *dlog.ZpDLog, y1 *big.Int) *QRProver {
	y, _ := dlog.Multiply(y1, y1)
	return &QRProver{
		DLog: dlog,
		Y:    y,
		y1:   y1,
	}
}

func (prover *QRProver) GetProofRandomData() *big.Int {
	r := common.GetRandomInt(prover.DLog.P)
	prover.r = r
	x, _ := prover.DLog.Exponentiate(r, big.NewInt(2))
	return x
}

func (prover *QRProver) GetProofData(challenge *big.Int) (*big.Int, error) {
	if challenge.Cmp(big.NewInt(0)) == 0 {
		return prover.r, nil
	} else if challenge.Cmp(big.NewInt(1)) == 0 {
		z := new(big.Int).Mul(prover.r, prover.y1)
		z.Mod(z, prover.DLog.P)
		return z, nil
	} else {
		err := errors.New("The challenge is not valid.")
		return nil, err
	}
}

type QRVerifier struct {
	DLog      *dlog.ZpDLog
	x         *big.Int
	y         *big.Int
	challenge *big.Int
}

func NewQRVerifier(y *big.Int, dlog *dlog.ZpDLog) *QRVerifier {
	return &QRVerifier{
		DLog: dlog,
		y:    y,
	}
}

func (verifier *QRVerifier) GetChallenge(x *big.Int) *big.Int {
	verifier.x = x
	c := common.GetRandomInt(big.NewInt(2)) // 0 or 1
	verifier.challenge = c
	return c
}

func (verifier *QRVerifier) Verify(z *big.Int) bool {
	z2 := new(big.Int).Mul(z, z)
	z2.Mod(z2, verifier.DLog.P)
	if verifier.challenge.Cmp(big.NewInt(0)) == 0 {
		return z2.Cmp(verifier.x) == 0
	} else {
		s := new(big.Int).Mul(verifier.x, verifier.y)
		s.Mod(s, verifier.DLog.P)
		return z2.Cmp(s) == 0
	}
}
