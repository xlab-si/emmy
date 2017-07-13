package pseudonymsys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"math/big"
)

type PseudonymEC struct {
	A *common.ECGroupElement
	B *common.ECGroupElement
}

func NewPseudonymEC(a, b *common.ECGroupElement) *PseudonymEC {
	return &PseudonymEC{
		A: a,
		B: b,
	}
}

type OrgNymGenEC struct {
	EqualityVerifier *dlogproofs.ECDLogEqualityVerifier
}

func NewOrgNymGenEC() *OrgNymGenEC {
	verifier := dlogproofs.NewECDLogEqualityVerifier(dlog.P256)
	org := OrgNymGenEC{
		EqualityVerifier: verifier,
	}
	return &org
}

func (org *OrgNymGenEC) GetChallenge(nymA, blindedA, nymB, blindedB,
	x1, x2 *common.ECGroupElement, r, s *big.Int) (*big.Int, error) {
	x, y := config.LoadPseudonymsysCAPubKey()
	c := elliptic.P256()
	pubKey := ecdsa.PublicKey{Curve: c, X: x, Y: y}

	hashed := common.HashIntoBytes(blindedA.X, blindedA.Y, blindedB.X, blindedB.Y)
	verified := ecdsa.Verify(&pubKey, hashed, r, s)
	if verified {
		challenge := org.EqualityVerifier.GetChallenge(nymA, blindedA, nymB, blindedB, x1, x2)
		return challenge, nil
	} else {
		return nil, fmt.Errorf("The signature is not valid.")
	}
}

func (org *OrgNymGenEC) Verify(z *big.Int) bool {
	verified := org.EqualityVerifier.Verify(z)
	if verified {
		// TODO: store (a, b) into a database
	}
	return verified
}
