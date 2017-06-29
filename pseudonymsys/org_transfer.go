package pseudonymsys

import (
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"math/big"
)

type OrgCredentialVerifier struct {
	DLog *dlog.ZpDLog
	s1   *big.Int
	s2   *big.Int

	EqualityVerifier *dlogproofs.DLogEqualityVerifier
	a                *big.Int
	b                *big.Int
}

func NewOrgCredentialVerifier() *OrgCredentialVerifier {
	dlog := config.LoadDLog("pseudonymsys")
	// this presumes that organization's own keys are stored under "org1"
	s1, s2 := config.LoadPseudonymsysOrgSecrets("org1")

	equalityVerifier := dlogproofs.NewDLogEqualityVerifier(dlog)
	org := OrgCredentialVerifier{
		DLog:             dlog,
		s1:               s1,
		s2:               s2,
		EqualityVerifier: equalityVerifier,
	}

	return &org
}

func (org *OrgCredentialVerifier) GetAuthenticationChallenge(a, b, a1, b1, x1, x2 *big.Int) *big.Int {
	// TODO: check if (a, b) is registered; if not, close the session

	org.a = a
	org.b = b
	challenge := org.EqualityVerifier.GetChallenge(a, a1, b, b1, x1, x2)
	return challenge
}

func (org *OrgCredentialVerifier) VerifyAuthentication(z *big.Int,
	credential *Credential, orgPubKeys *OrgPubKeys) bool {
	verified := org.EqualityVerifier.Verify(z)
	if !verified {
		// TODO: close the session
	}

	valid1 := dlogproofs.VerifyBlindedTranscript(credential.T1, org.DLog, org.DLog.G, orgPubKeys.H2,
		credential.SmallBToGamma, credential.AToGamma)

	aAToGamma, _ := org.DLog.Multiply(credential.SmallAToGamma, credential.AToGamma)
	valid2 := dlogproofs.VerifyBlindedTranscript(credential.T2, org.DLog, org.DLog.G, orgPubKeys.H1,
		aAToGamma, credential.BToGamma)

	if valid1 && valid2 {
		return true
	} else {
		// TODO: close the session

		return false
	}

}
