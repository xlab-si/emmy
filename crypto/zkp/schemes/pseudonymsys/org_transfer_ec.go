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

	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
)

type OrgCredentialVerifierEC struct {
	s1 *big.Int
	s2 *big.Int

	EqualityVerifier *dlogproofs.ECDLogEqualityVerifier
	a                *groups.ECGroupElement
	b                *groups.ECGroupElement
	curveType        groups.ECurve
}

func NewOrgCredentialVerifierEC(s1, s2 *big.Int, curveType groups.ECurve) *OrgCredentialVerifierEC {
	equalityVerifier := dlogproofs.NewECDLogEqualityVerifier(curveType)
	org := OrgCredentialVerifierEC{
		s1:               s1,
		s2:               s2,
		EqualityVerifier: equalityVerifier,
		curveType:        curveType,
	}

	return &org
}

func (org *OrgCredentialVerifierEC) GetAuthenticationChallenge(a, b, a1, b1,
	x1, x2 *groups.ECGroupElement) *big.Int {
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

	g := groups.NewECGroupElement(org.EqualityVerifier.Group.Curve.Params().Gx,
		org.EqualityVerifier.Group.Curve.Params().Gy)

	valid1 := dlogproofs.VerifyBlindedTranscriptEC(credential.T1, groups.P256, g, orgPubKeys.H2,
		credential.SmallBToGamma, credential.AToGamma)

	aAToGamma := org.EqualityVerifier.Group.Mul(credential.SmallAToGamma, credential.AToGamma)
	valid2 := dlogproofs.VerifyBlindedTranscriptEC(credential.T2, groups.P256, g, orgPubKeys.H1,
		aAToGamma, credential.BToGamma)

	return valid1 && valid2
}
