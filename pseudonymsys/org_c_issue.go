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
	EqualityProver1 *dlogproofs.DLogEqualityBTranscriptProver
	EqualityProver2 *dlogproofs.DLogEqualityBTranscriptProver
	a *big.Int
	b *big.Int
}

func NewOrgCredentialIssuer(orgName string) (*OrgCredentialIssuer) {
	dlog := config.LoadPseudonymsysDLog()
	s1, s2 := config.LoadPseudonymsysOrgSecrets(orgName)

	// g1 = a_tilde, t1 = b_tilde,
	// g2 = a, t2 = b
	schnorrVerifier := dlogproofs.NewSchnorrVerifier(dlog, common.Sigma)
	equalityProver1 := dlogproofs.NewDLogEqualityBTranscriptProver(dlog)
	equalityProver2 := dlogproofs.NewDLogEqualityBTranscriptProver(dlog)
	org := OrgCredentialIssuer {
		DLog: dlog,	
		s1: s1,
		s2: s2,
		SchnorrVerifier: schnorrVerifier,
		EqualityProver1: equalityProver1,
		EqualityProver2: equalityProver2,
	}
	
	return &org
}

func (org *OrgCredentialIssuer) GetAuthenticationChallenge(a, b, x *big.Int) *big.Int {
	// TODO: check if (a, b) is registered; if not, close the session

	org.a = a
	org.b = b
	org.SchnorrVerifier.SetProofRandomData(x, a, b)
	challenge, _ := org.SchnorrVerifier.GetChallenge()
	return challenge
}

// Verifies that user knows log_a(b). Sends back proof random data (g1^r, g2^r) for both equality proofs.
func (org *OrgCredentialIssuer) VerifyAuthentication(z *big.Int) (
		*big.Int, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
	verified := org.SchnorrVerifier.Verify(z, nil)
	if verified {
		A, _ := org.DLog.Exponentiate(org.b, org.s2)	
		aA, _ := org.DLog.Multiply(org.a, A)
		B, _ := org.DLog.Exponentiate(aA, org.s1)
		
		x11, x12 := org.EqualityProver1.GetProofRandomData(org.s2, org.DLog.G, org.b)
		x21, x22 := org.EqualityProver2.GetProofRandomData(org.s1, org.DLog.G, aA)
		
		return x11, x12, x21, x22, A, B, nil	
	} else {
		// TODO: close the session

		err := errors.New("Authentication with organization failed")	
		return nil, nil, nil, nil, nil, nil, err
	}
}

func (org *OrgCredentialIssuer) GetEqualityProofData(challenge1, 
		challenge2 *big.Int) (*big.Int, *big.Int) {
	z1 := org.EqualityProver1.GetProofData(challenge1)
	z2 := org.EqualityProver2.GetProofData(challenge2)
	return z1, z2
}

	
	
	