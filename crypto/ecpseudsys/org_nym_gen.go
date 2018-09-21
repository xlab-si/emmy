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

package ecpseudsys

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/ec"
	"github.com/xlab-si/emmy/crypto/ecschnorr"
	"github.com/xlab-si/emmy/crypto/pseudsys"
)

// Nym represents a pseudonym in the pseudonym system scheme.
type Nym struct {
	A *ec.GroupElement
	B *ec.GroupElement
}

func NewNym(a, b *ec.GroupElement) *Nym {
	return &Nym{
		A: a,
		B: b,
	}
}

type NymGenerator struct {
	verifier  *ecschnorr.EqualityVerifier
	caPubKey  *pseudsys.PubKey
	curveType ec.Curve
}

func NewNymGenerator(pubKey *pseudsys.PubKey, c ec.Curve) *NymGenerator {
	return &NymGenerator{
		verifier:  ecschnorr.NewEqualityVerifier(c),
		caPubKey:  pubKey,
		curveType: c,
	}
}

func (g *NymGenerator) GetChallenge(nymA, blindedA, nymB, blindedB,
	x1, x2 *ec.GroupElement, r, s *big.Int) (*big.Int, error) {
	c := ec.GetCurve(g.curveType)
	pubKey := ecdsa.PublicKey{Curve: c, X: g.caPubKey.H1, Y: g.caPubKey.H2}

	hashed := common.HashIntoBytes(blindedA.X, blindedA.Y, blindedB.X, blindedB.Y)

	if verified := ecdsa.Verify(&pubKey, hashed, r, s); !verified {
		return nil, fmt.Errorf("signature is not valid")
	}

	challenge := g.verifier.GetChallenge(nymA, blindedA, nymB, blindedB, x1, x2)
	return challenge, nil
}

// TODO: store (a, b) into a database if verified
func (g *NymGenerator) Verify(z *big.Int) bool {
	return g.verifier.Verify(z)
}
