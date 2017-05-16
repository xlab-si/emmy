package pseudonymsys

import (
	"math/big"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
)

type OrgNymGenMasterVerifier struct {
	DLog *dlog.ZpDLog
	EqualityVerifier *dlogproofs.DLogEqualityVerifier
}

func NewOrgNymGenMasterVerifier(orgName string) (*OrgNymGenMasterVerifier) {
	dlog := config.LoadPseudonymsysDLog()
	verifier := dlogproofs.NewDLogEqualityVerifier(dlog)
	org := OrgNymGenMasterVerifier {
		DLog: dlog,	
		EqualityVerifier: verifier,
	}
	return &org
}

func (org *OrgNymGenMasterVerifier) GetChallenge(nymA, blindedA, nymB, blindedB, 
		x1, x2, r, s *big.Int, caName string) (*big.Int, error) {
	x, y := config.LoadPseudonymsysCAPubKey(caName)
	c := elliptic.P256()
	pubKey := ecdsa.PublicKey{Curve: c, X: x, Y: y}
	
	hashed := common.HashIntoBytes(blindedA, blindedB)
	verified := ecdsa.Verify(&pubKey, hashed, r, s)
	if verified {
		challenge := org.EqualityVerifier.GetChallenge(nymA, blindedA, nymB, blindedB, x1, x2)
		return challenge, nil
	} else {
		// TODO: end session

		err := errors.New("The signature is not valid.")	
		return nil, err
	}		
}

func (org *OrgNymGenMasterVerifier) Verify(z *big.Int) bool {
	verified := org.EqualityVerifier.Verify(z)
	if verified {
		// TODO: store (a, b) into a database	
	}
	return verified
}



	
