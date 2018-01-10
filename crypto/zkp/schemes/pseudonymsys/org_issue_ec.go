/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package pseudonymsys

import (
	"math/big"

	"fmt"

	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/protocoltypes"
)

type CredentialEC struct {
	SmallAToGamma *groups.ECGroupElement
	SmallBToGamma *groups.ECGroupElement
	AToGamma      *groups.ECGroupElement
	BToGamma      *groups.ECGroupElement
	T1            *dlogproofs.TranscriptEC
	T2            *dlogproofs.TranscriptEC
}

func NewCredentialEC(aToGamma, bToGamma, AToGamma, BToGamma *groups.ECGroupElement,
	t1, t2 *dlogproofs.TranscriptEC) *CredentialEC {
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
	H1 *groups.ECGroupElement
	H2 *groups.ECGroupElement
}

func NewOrgPubKeysEC(h1, h2 *groups.ECGroupElement) *OrgPubKeysEC {
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
	a               *groups.ECGroupElement
	b               *groups.ECGroupElement
}

func NewOrgCredentialIssuerEC(s1, s2 *big.Int, curveType groups.ECurve) *OrgCredentialIssuerEC {
	// g1 = a_tilde, t1 = b_tilde,
	// g2 = a, t2 = b
	schnorrVerifier := dlogproofs.NewSchnorrECVerifier(curveType, protocoltypes.Sigma)
	equalityProver1 := dlogproofs.NewECDLogEqualityBTranscriptProver(curveType)
	equalityProver2 := dlogproofs.NewECDLogEqualityBTranscriptProver(curveType)
	org := OrgCredentialIssuerEC{
		s1:              s1,
		s2:              s2,
		SchnorrVerifier: schnorrVerifier,
		EqualityProver1: equalityProver1,
		EqualityProver2: equalityProver2,
	}

	return &org
}

func (org *OrgCredentialIssuerEC) GetAuthenticationChallenge(a, b, x *groups.ECGroupElement) *big.Int {
	// TODO: check if (a, b) is registered; if not, close the session

	org.a = a
	org.b = b
	org.SchnorrVerifier.SetProofRandomData(x, a, b)
	challenge, _ := org.SchnorrVerifier.GetChallenge()
	return challenge
}

// Verifies that user knows log_a(b). Sends back proof random data (g1^r, g2^r) for both equality proofs.
func (org *OrgCredentialIssuerEC) VerifyAuthentication(z *big.Int) (
	*groups.ECGroupElement, *groups.ECGroupElement, *groups.ECGroupElement,
	*groups.ECGroupElement, *groups.ECGroupElement, *groups.ECGroupElement, error) {
	verified := org.SchnorrVerifier.Verify(z, nil)
	if verified {
		A := org.SchnorrVerifier.Group.Exp(org.b, org.s2)
		aA := org.SchnorrVerifier.Group.Mul(org.a, A)
		B := org.SchnorrVerifier.Group.Exp(aA, org.s1)

		g1 := groups.NewECGroupElement(org.SchnorrVerifier.Group.Curve.Params().Gx,
			org.SchnorrVerifier.Group.Curve.Params().Gy)
		g2 := groups.NewECGroupElement(org.b.X, org.b.Y)

		x11, x12 := org.EqualityProver1.GetProofRandomData(org.s2, g1, g2)
		x21, x22 := org.EqualityProver2.GetProofRandomData(org.s1, g1, aA)

		return x11, x12, x21, x22, A, B, nil
	} else {
		err := fmt.Errorf("authentication with organization failed")
		return nil, nil, nil, nil, nil, nil, err
	}
}

func (org *OrgCredentialIssuerEC) GetEqualityProofData(challenge1,
	challenge2 *big.Int) (*big.Int, *big.Int) {
	z1 := org.EqualityProver1.GetProofData(challenge1)
	z2 := org.EqualityProver2.GetProofData(challenge2)
	return z1, z2
}
