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
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/ec"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
)

type PseudonymEC struct {
	A *ec.GroupElement
	B *ec.GroupElement
}

func NewPseudonymEC(a, b *ec.GroupElement) *PseudonymEC {
	return &PseudonymEC{
		A: a,
		B: b,
	}
}

type OrgNymGenEC struct {
	EqualityVerifier *dlogproofs.ECDLogEqualityVerifier
	caPubKey         *PubKey
	curveType        ec.Curve
}

func NewOrgNymGenEC(pubKey *PubKey, curveType ec.Curve) *OrgNymGenEC {
	verifier := dlogproofs.NewECDLogEqualityVerifier(curveType)
	org := OrgNymGenEC{
		EqualityVerifier: verifier,
		caPubKey:         pubKey,
		curveType:        curveType,
	}
	return &org
}

func (org *OrgNymGenEC) GetChallenge(nymA, blindedA, nymB, blindedB,
	x1, x2 *ec.GroupElement, r, s *big.Int) (*big.Int, error) {
	c := ec.GetCurve(org.curveType)
	pubKey := ecdsa.PublicKey{Curve: c, X: org.caPubKey.H1, Y: org.caPubKey.H2}

	hashed := common.HashIntoBytes(blindedA.X, blindedA.Y, blindedB.X, blindedB.Y)
	verified := ecdsa.Verify(&pubKey, hashed, r, s)
	if verified {
		challenge := org.EqualityVerifier.GetChallenge(nymA, blindedA, nymB, blindedB, x1, x2)
		return challenge, nil
	} else {
		return nil, fmt.Errorf("signature is not valid")
	}
}

func (org *OrgNymGenEC) Verify(z *big.Int) bool {
	verified := org.EqualityVerifier.Verify(z)
	if verified {
		// TODO: store (a, b) into a database
	}
	return verified
}
