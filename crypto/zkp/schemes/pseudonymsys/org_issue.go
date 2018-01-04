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
	"errors"
	"math/big"

	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/types"
)

type Credential struct {
	SmallAToGamma *big.Int
	SmallBToGamma *big.Int
	AToGamma      *big.Int
	BToGamma      *big.Int
	T1            *dlogproofs.Transcript
	T2            *dlogproofs.Transcript
}

func NewCredential(aToGamma, bToGamma, AToGamma, BToGamma *big.Int,
	t1, t2 *dlogproofs.Transcript) *Credential {
	credential := &Credential{
		SmallAToGamma: aToGamma,
		SmallBToGamma: bToGamma,
		AToGamma:      AToGamma,
		BToGamma:      BToGamma,
		T1:            t1,
		T2:            t2,
	}
	return credential
}

type OrgPubKeys struct {
	H1 *big.Int
	H2 *big.Int
}

func NewOrgPubKeys(h1, h2 *big.Int) *OrgPubKeys {
	return &OrgPubKeys{
		H1: h1,
		H2: h2,
	}
}

type OrgCredentialIssuer struct {
	Group *groups.SchnorrGroup
	s1    *big.Int
	s2    *big.Int

	// the following fields are needed for issuing a credential
	SchnorrVerifier *dlogproofs.SchnorrVerifier
	EqualityProver1 *dlogproofs.DLogEqualityBTranscriptProver
	EqualityProver2 *dlogproofs.DLogEqualityBTranscriptProver
	a               *big.Int
	b               *big.Int
}

func NewOrgCredentialIssuer(group *groups.SchnorrGroup, s1, s2 *big.Int) *OrgCredentialIssuer {
	// g1 = a_tilde, t1 = b_tilde,
	// g2 = a, t2 = b
	schnorrVerifier := dlogproofs.NewSchnorrVerifier(group, types.Sigma)
	equalityProver1 := dlogproofs.NewDLogEqualityBTranscriptProver(group)
	equalityProver2 := dlogproofs.NewDLogEqualityBTranscriptProver(group)
	org := OrgCredentialIssuer{
		Group:           group,
		s1:              s1,
		s2:              s2,
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
		A := org.Group.Exp(org.b, org.s2)
		aA := org.Group.Mul(org.a, A)
		B := org.Group.Exp(aA, org.s1)

		x11, x12 := org.EqualityProver1.GetProofRandomData(org.s2, org.Group.G, org.b)
		x21, x22 := org.EqualityProver2.GetProofRandomData(org.s1, org.Group.G, aA)

		return x11, x12, x21, x22, A, B, nil
	} else {
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
