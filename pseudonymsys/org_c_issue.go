package pseudonymsys

import (
	"math/big"
	"errors"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
)

type OrgCredentialIssuer struct {
	DLog *dlog.ZpDLog
	s1 *big.Int
	s2 *big.Int
	
	// the following fields are needed for issuing a credential
	SchnorrVerifier *dlogproofs.SchnorrVerifier
	EqualityVerifier *dlogproofs.DLogEqualityBTranscriptVerifier
	a *big.Int
	b *big.Int
}

func NewOrgCredentialIssuer(orgName string) (*OrgCredentialIssuer) {
	dlog := config.LoadPseudonymsysDLogFromConfig()
	s1, s2 := config.LoadPseudonymsysOrgSecretsFromConfig(orgName)

	// g1 = a_tilde, t1 = b_tilde,
	// g2 = a, t2 = b
	schnorrVerifier := dlogproofs.NewSchnorrVerifier(dlog, common.Sigma)
	eVerifier := dlogproofs.NewDLogEqualityBTranscriptVerifier(dlog)
	org := OrgCredentialIssuer {
		DLog: dlog,	
		s1: s1,
		s2: s2,
		SchnorrVerifier: schnorrVerifier,
		EqualityVerifier: eVerifier,
	}
	
	return &org
}

func (org *OrgCredentialIssuer) GetAuthenticationChallenge(a, b, x *big.Int) *big.Int {
	// TODO: check if (a, b) is registered

	org.a = a
	org.b = b
	org.SchnorrVerifier.SetProofRandomData(x, a, b)
	challenge, _ := org.SchnorrVerifier.GetChallenge()
	return challenge
}

func (org *OrgCredentialIssuer) VerifyAuthentication(z *big.Int) (*big.Int, *big.Int, error) {
	verified := org.SchnorrVerifier.Verify(z, nil)
	if verified {
		A, _ := org.DLog.Exponentiate(org.b, org.s2)	
		B, _ := org.DLog.Multiply(org.a, A)
		B, _ = org.DLog.Exponentiate(B, org.s1)
		
		return A, B, nil	
	} else {
		err := errors.New("Authentication with organization failed")	
		return nil, nil, err
	}
}


	

	
	
	