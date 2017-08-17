package pseudonymsys

import (
	"errors"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/dlogproofs"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

type CredentialEC struct {
	SmallAToGamma *types.ECGroupElement
	SmallBToGamma *types.ECGroupElement
	AToGamma      *types.ECGroupElement
	BToGamma      *types.ECGroupElement
	T1            []*big.Int
	T2            []*big.Int
}

func NewCredentialEC(aToGamma, bToGamma, AToGamma, BToGamma *types.ECGroupElement,
	t1, t2 []*big.Int) *CredentialEC {
	credential := &CredentialEC{
		SmallAToGamma: aToGamma,
		SmallBToGamma: bToGamma,
		AToGamma:      AToGamma,
		BToGamma:      BToGamma,
		T1:            t1,
		T2:            t2,
	}
	return credential
}

type OrgPubKeysEC struct {
	H1 *types.ECGroupElement
	H2 *types.ECGroupElement
}

func NewOrgPubKeysEC(h1, h2 *types.ECGroupElement) *OrgPubKeysEC {
	return &OrgPubKeysEC{
		H1: h1,
		H2: h2,
	}
}

type OrgCredentialIssuerEC struct {
	s1 *big.Int
	s2 *big.Int

	// the following fields are needed for issuing a credential
	SchnorrVerifier *dlogproofs.SchnorrECVerifier
	EqualityProver1 *dlogproofs.ECDLogEqualityBTranscriptProver
	EqualityProver2 *dlogproofs.ECDLogEqualityBTranscriptProver
	a               *types.ECGroupElement
	b               *types.ECGroupElement
}

func NewOrgCredentialIssuerEC() *OrgCredentialIssuerEC {
	// this presumes that organization's own keys are stored under "org1"
	s1, s2 := config.LoadPseudonymsysOrgSecrets("org1", "ecdlog")

	// g1 = a_tilde, t1 = b_tilde,
	// g2 = a, t2 = b
	schnorrVerifier := dlogproofs.NewSchnorrECVerifier(dlog.P256, types.Sigma)
	equalityProver1 := dlogproofs.NewECDLogEqualityBTranscriptProver(dlog.P256)
	equalityProver2 := dlogproofs.NewECDLogEqualityBTranscriptProver(dlog.P256)
	org := OrgCredentialIssuerEC{
		s1:              s1,
		s2:              s2,
		SchnorrVerifier: schnorrVerifier,
		EqualityProver1: equalityProver1,
		EqualityProver2: equalityProver2,
	}

	return &org
}

func (org *OrgCredentialIssuerEC) GetAuthenticationChallenge(a, b, x *types.ECGroupElement) *big.Int {
	// TODO: check if (a, b) is registered; if not, close the session

	org.a = a
	org.b = b
	org.SchnorrVerifier.SetProofRandomData(x, a, b)
	challenge, _ := org.SchnorrVerifier.GetChallenge()
	return challenge
}

// Verifies that user knows log_a(b). Sends back proof random data (g1^r, g2^r) for both equality proofs.
func (org *OrgCredentialIssuerEC) VerifyAuthentication(z *big.Int) (
	*types.ECGroupElement, *types.ECGroupElement, *types.ECGroupElement,
	*types.ECGroupElement, *types.ECGroupElement, *types.ECGroupElement, error) {
	verified := org.SchnorrVerifier.Verify(z, nil)
	if verified {
		A1, A2 := org.SchnorrVerifier.DLog.Exponentiate(org.b.X, org.b.Y, org.s2)
		aA1, aA2 := org.SchnorrVerifier.DLog.Multiply(org.a.X, org.a.Y, A1, A2)
		B1, B2 := org.SchnorrVerifier.DLog.Exponentiate(aA1, aA2, org.s1)

		A := types.NewECGroupElement(A1, A2)
		B := types.NewECGroupElement(B1, B2)

		g1 := types.NewECGroupElement(org.SchnorrVerifier.DLog.Curve.Params().Gx,
			org.SchnorrVerifier.DLog.Curve.Params().Gy)
		g2 := types.NewECGroupElement(org.b.X, org.b.Y)
		g3 := types.NewECGroupElement(aA1, aA2)

		x11, x12 := org.EqualityProver1.GetProofRandomData(org.s2, g1, g2)
		x21, x22 := org.EqualityProver2.GetProofRandomData(org.s1, g1, g3)

		return x11, x12, x21, x22, A, B, nil
	} else {
		err := errors.New("Authentication with organization failed")
		return nil, nil, nil, nil, nil, nil, err
	}
}

func (org *OrgCredentialIssuerEC) GetEqualityProofData(challenge1,
	challenge2 *big.Int) (*big.Int, *big.Int) {
	z1 := org.EqualityProver1.GetProofData(challenge1)
	z2 := org.EqualityProver2.GetProofData(challenge2)
	return z1, z2
}
