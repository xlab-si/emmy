package pseudonymsys

import (
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"math/big"
)

type OrgCredentialVerifierEC struct {
	s1 *big.Int
	s2 *big.Int

	EqualityVerifier *dlogproofs.ECDLogEqualityVerifier
	a                *common.ECGroupElement
	b                *common.ECGroupElement
}

func NewOrgCredentialVerifierEC() *OrgCredentialVerifierEC {
	// this presumes that organization's own keys are stored under "org1"
	s1, s2 := config.LoadPseudonymsysOrgSecrets("org1", "ecdlog")

	equalityVerifier := dlogproofs.NewECDLogEqualityVerifier(dlog.P256)
	org := OrgCredentialVerifierEC{
		s1:               s1,
		s2:               s2,
		EqualityVerifier: equalityVerifier,
	}

	return &org
}

func (org *OrgCredentialVerifierEC) GetAuthenticationChallenge(a, b, a1, b1,
	x1, x2 *common.ECGroupElement) *big.Int {
	// TODO: check if (a, b) is registered; if not, close the session

	org.a = a
	org.b = b
	challenge := org.EqualityVerifier.GetChallenge(a, a1, b, b1, x1, x2)
	return challenge
}

func (org *OrgCredentialVerifierEC) VerifyAuthentication(z *big.Int,
	credential *CredentialEC, orgPubKeys *OrgPubKeysEC) bool {
	verified := org.EqualityVerifier.Verify(z)
	if !verified {
		return false
	}

	g := common.NewECGroupElement(org.EqualityVerifier.DLog.Curve.Params().Gx,
		org.EqualityVerifier.DLog.Curve.Params().Gy)

	valid1 := dlogproofs.VerifyBlindedTranscriptEC(credential.T1, dlog.P256, g, orgPubKeys.H2,
		credential.SmallBToGamma, credential.AToGamma)

	aAToGamma1, aAToGamma2 := org.EqualityVerifier.DLog.Multiply(credential.SmallAToGamma.X,
		credential.SmallAToGamma.Y, credential.AToGamma.X, credential.AToGamma.Y)
	aAToGamma := common.NewECGroupElement(aAToGamma1, aAToGamma2)
	valid2 := dlogproofs.VerifyBlindedTranscriptEC(credential.T2, dlog.P256, g, orgPubKeys.H1,
		aAToGamma, credential.BToGamma)

	if valid1 && valid2 {
		return true
	} else {
		return false
	}
}
