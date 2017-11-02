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
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
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

func NewOrgCredentialVerifier(dlog *dlog.ZpDLog, s1, s2 *big.Int) *OrgCredentialVerifier {
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
		return false
	}

	valid1 := dlogproofs.VerifyBlindedTranscript(credential.T1, org.DLog, org.DLog.G, orgPubKeys.H2,
		credential.SmallBToGamma, credential.AToGamma)

	aAToGamma, _ := org.DLog.Multiply(credential.SmallAToGamma, credential.AToGamma)
	valid2 := dlogproofs.VerifyBlindedTranscript(credential.T2, org.DLog, org.DLog.G, orgPubKeys.H1,
		aAToGamma, credential.BToGamma)

	if valid1 && valid2 {
		return true
	} else {
		return false
	}

}
