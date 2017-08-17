package pseudonymsys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlogproofs"
	"math/big"
)

type Pseudonym struct {
	A *big.Int
	B *big.Int
}

func NewPseudonym(a, b *big.Int) *Pseudonym {
	return &Pseudonym{
		A: a,
		B: b,
	}
}

type OrgNymGen struct {
	EqualityVerifier *dlogproofs.DLogEqualityVerifier
}

func NewOrgNymGen() *OrgNymGen {
	dlog := config.LoadDLog("pseudonymsys")
	verifier := dlogproofs.NewDLogEqualityVerifier(dlog)
	org := OrgNymGen{
		EqualityVerifier: verifier,
	}
	return &org
}

func (org *OrgNymGen) GetChallenge(nymA, blindedA, nymB, blindedB,
	x1, x2, r, s *big.Int) (*big.Int, error) {
	x, y := config.LoadPseudonymsysCAPubKey()
	c := elliptic.P256()
	pubKey := ecdsa.PublicKey{Curve: c, X: x, Y: y}

	hashed := common.HashIntoBytes(blindedA, blindedB)
	verified := ecdsa.Verify(&pubKey, hashed, r, s)
	if verified {
		challenge := org.EqualityVerifier.GetChallenge(nymA, blindedA, nymB, blindedB, x1, x2)
		return challenge, nil
	} else {
		return nil, fmt.Errorf("The signature is not valid.")
	}
}

func (org *OrgNymGen) Verify(z *big.Int) bool {
	verified := org.EqualityVerifier.Verify(z)
	if verified {
		// TODO: store (a, b) into a database
	}
	return verified
}
