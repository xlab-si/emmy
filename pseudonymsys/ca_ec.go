package pseudonymsys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"math/big"
)

type CAEC struct {
	DLog            *dlog.ECDLog
	SchnorrVerifier *dlogproofs.SchnorrECVerifier
	a               *common.ECGroupElement
	b               *common.ECGroupElement
	privateKey      *ecdsa.PrivateKey
}

type CACertificateEC struct {
	BlindedA *common.ECGroupElement
	BlindedB *common.ECGroupElement
	R        *big.Int
	S        *big.Int
}

func NewCACertificateEC(blindedA, blindedB *common.ECGroupElement, r, s *big.Int) *CACertificateEC {
	return &CACertificateEC{
		BlindedA: blindedA,
		BlindedB: blindedB,
		R:        r,
		S:        s,
	}
}

func NewCAEC() *CAEC {
	x, y := config.LoadPseudonymsysCAPubKey()
	d := config.LoadPseudonymsysCASecret()

	c := elliptic.P256()
	pubKey := ecdsa.PublicKey{Curve: c, X: x, Y: y}
	privateKey := ecdsa.PrivateKey{PublicKey: pubKey, D: d}

	schnorrVerifier := dlogproofs.NewSchnorrECVerifier(dlog.P256, common.Sigma)
	ca := CAEC{
		SchnorrVerifier: schnorrVerifier,
		privateKey:      &privateKey,
	}

	return &ca
}

func (ca *CAEC) GetChallenge(a, b, x *common.ECGroupElement) *big.Int {
	// TODO: check if b is really a valuable external user's public master key; if not, close the session

	ca.a = a
	ca.b = b
	ca.SchnorrVerifier.SetProofRandomData(x, a, b)
	challenge, _ := ca.SchnorrVerifier.GetChallenge()
	return challenge
}

func (ca *CAEC) Verify(z *big.Int) (*CACertificateEC, error) {
	verified := ca.SchnorrVerifier.Verify(z, nil)
	if verified {
		r := common.GetRandomInt(ca.SchnorrVerifier.DLog.OrderOfSubgroup)
		blindedA1, blindedA2 := ca.SchnorrVerifier.DLog.Exponentiate(ca.a.X, ca.a.Y, r)
		blindedB1, blindedB2 := ca.SchnorrVerifier.DLog.Exponentiate(ca.b.X, ca.b.Y, r)
		// blindedA, blindedB must be used only once (never use the same pair for two
		// different organizations)

		hashed := common.HashIntoBytes(blindedA1, blindedA2, blindedB1, blindedB2)
		r, s, err := ecdsa.Sign(rand.Reader, ca.privateKey, hashed)
		if err != nil {
			return nil, err
		} else {
			blindedA := common.NewECGroupElement(blindedA1, blindedA2)
			blindedB := common.NewECGroupElement(blindedB1, blindedB2)
			return NewCACertificateEC(blindedA, blindedB, r, s), nil
		}
	} else {
		return nil, fmt.Errorf("The knowledge of secret was not verified.")
	}
}
