package pseudonymsys

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/dlogproofs"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

type PseudonymEC struct {
	A *types.ECGroupElement
	B *types.ECGroupElement
}

func NewPseudonymEC(a, b *types.ECGroupElement) *PseudonymEC {
	return &PseudonymEC{
		A: a,
		B: b,
	}
}

type OrgNymGenEC struct {
	EqualityVerifier *dlogproofs.ECDLogEqualityVerifier
	x                *big.Int
	y                *big.Int
	curveType        dlog.Curve
}

func NewOrgNymGenEC(x, y *big.Int, curveType dlog.Curve) *OrgNymGenEC {
	verifier := dlogproofs.NewECDLogEqualityVerifier(curveType)
	org := OrgNymGenEC{
		EqualityVerifier: verifier,
		x:                x,
		y:                y,
		curveType:        curveType,
	}
	return &org
}

func (org *OrgNymGenEC) GetChallenge(nymA, blindedA, nymB, blindedB,
	x1, x2 *types.ECGroupElement, r, s *big.Int) (*big.Int, error) {
	c := dlog.GetEllipticCurve(org.curveType)
	pubKey := ecdsa.PublicKey{Curve: c, X: org.x, Y: org.y}

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
