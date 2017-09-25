package pseudonymsys

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/dlogproofs"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

type CA struct {
	SchnorrVerifier *dlogproofs.SchnorrVerifier
	a               *big.Int
	b               *big.Int
	privateKey      *ecdsa.PrivateKey
}

type CACertificate struct {
	BlindedA *big.Int
	BlindedB *big.Int
	R        *big.Int
	S        *big.Int
}

func NewCACertificate(blindedA, blindedB, r, s *big.Int) *CACertificate {
	return &CACertificate{
		BlindedA: blindedA,
		BlindedB: blindedB,
		R:        r,
		S:        s,
	}
}

func NewCA(zpdlog *dlog.ZpDLog, d, x, y *big.Int) *CA {
	c := dlog.GetEllipticCurve(dlog.P256)
	pubKey := ecdsa.PublicKey{Curve: c, X: x, Y: y}
	privateKey := ecdsa.PrivateKey{PublicKey: pubKey, D: d}

	schnorrVerifier := dlogproofs.NewSchnorrVerifier(zpdlog, types.Sigma)
	ca := CA{
		SchnorrVerifier: schnorrVerifier,
		privateKey:      &privateKey,
	}

	return &ca
}

func (ca *CA) GetChallenge(a, b, x *big.Int) *big.Int {
	// TODO: check if b is really a valuable external user's public master key; if not, close the session

	ca.a = a
	ca.b = b
	ca.SchnorrVerifier.SetProofRandomData(x, a, b)
	challenge, _ := ca.SchnorrVerifier.GetChallenge()
	return challenge
}

func (ca *CA) Verify(z *big.Int) (*CACertificate, error) {
	verified := ca.SchnorrVerifier.Verify(z, nil)
	if verified {
		r := common.GetRandomInt(ca.SchnorrVerifier.DLog.OrderOfSubgroup)
		blindedA, _ := ca.SchnorrVerifier.DLog.Exponentiate(ca.a, r)
		blindedB, _ := ca.SchnorrVerifier.DLog.Exponentiate(ca.b, r)
		// blindedA, blindedB must be used only once (never use the same pair for two
		// different organizations)

		hashed := common.HashIntoBytes(blindedA, blindedB)
		r, s, err := ecdsa.Sign(rand.Reader, ca.privateKey, hashed)
		if err != nil {
			return nil, err
		} else {
			return NewCACertificate(blindedA, blindedB, r, s), nil
		}
	} else {
		return nil, fmt.Errorf("The knowledge of secret was not verified.")
	}
}
