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
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/dlogproofs"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

type OrgCredentialVerifierEC struct {
	s1 *big.Int
	s2 *big.Int

	EqualityVerifier *dlogproofs.ECDLogEqualityVerifier
	a                *types.ECGroupElement
	b                *types.ECGroupElement
	curveType        dlog.Curve
}

func NewOrgCredentialVerifierEC(s1, s2 *big.Int, curveType dlog.Curve) *OrgCredentialVerifierEC {
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
	x1, x2 *types.ECGroupElement) *big.Int {
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

	g := types.NewECGroupElement(org.EqualityVerifier.DLog.Curve.Params().Gx,
		org.EqualityVerifier.DLog.Curve.Params().Gy)

	valid1 := dlogproofs.VerifyBlindedTranscriptEC(credential.T1, dlog.P256, g, orgPubKeys.H2,
		credential.SmallBToGamma, credential.AToGamma)

	aAToGamma1, aAToGamma2 := org.EqualityVerifier.DLog.Multiply(credential.SmallAToGamma.X,
		credential.SmallAToGamma.Y, credential.AToGamma.X, credential.AToGamma.Y)
	aAToGamma := types.NewECGroupElement(aAToGamma1, aAToGamma2)
	valid2 := dlogproofs.VerifyBlindedTranscriptEC(credential.T2, dlog.P256, g, orgPubKeys.H1,
		aAToGamma, credential.BToGamma)

	if valid1 && valid2 {
		return true
	} else {
		return false
	}
}
