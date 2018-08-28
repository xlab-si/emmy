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
	"github.com/xlab-si/emmy/crypto/schnorr"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
)

type Pseudonym struct {
	A *big.Int
	B *big.Int
}

func NewPseudonym(a, b *big.Int) *Pseudonym {
	return &Pseudonym{
		A: a,
		B: b,
	}
}

type OrgNymGen struct {
	EqualityVerifier *dlogproofs.DLogEqualityVerifier
	caPubKey         *PubKey
}

func NewOrgNymGen(group *schnorr.Group, caPubKey *PubKey) *OrgNymGen {
	verifier := dlogproofs.NewDLogEqualityVerifier(group)
	org := OrgNymGen{
		EqualityVerifier: verifier,
		caPubKey:         caPubKey,
	}
	return &org
}

func (org *OrgNymGen) GetChallenge(nymA, blindedA, nymB, blindedB, x1, x2,
	r, s *big.Int) (*big.Int, error) {
	c := ec.GetCurve(ec.P256)
	pubKey := ecdsa.PublicKey{Curve: c, X: org.caPubKey.H1, Y: org.caPubKey.H2}

	hashed := common.HashIntoBytes(blindedA, blindedB)
	verified := ecdsa.Verify(&pubKey, hashed, r, s)
	if verified {
		challenge := org.EqualityVerifier.GetChallenge(nymA, blindedA, nymB, blindedB, x1, x2)
		return challenge, nil
	} else {
		return nil, fmt.Errorf("signature is not valid")
	}
}

func (org *OrgNymGen) Verify(z *big.Int) bool {
	verified := org.EqualityVerifier.Verify(z)
	if verified {
		// TODO: store (a, b) into a database
	}
	return verified
}
