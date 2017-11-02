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
	"crypto/rand"
	"fmt"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

type CAEC struct {
	DLog            *dlog.ECDLog
	SchnorrVerifier *dlogproofs.SchnorrECVerifier
	a               *types.ECGroupElement
	b               *types.ECGroupElement
	privateKey      *ecdsa.PrivateKey
}

type CACertificateEC struct {
	BlindedA *types.ECGroupElement
	BlindedB *types.ECGroupElement
	R        *big.Int
	S        *big.Int
}

func NewCACertificateEC(blindedA, blindedB *types.ECGroupElement, r, s *big.Int) *CACertificateEC {
	return &CACertificateEC{
		BlindedA: blindedA,
		BlindedB: blindedB,
		R:        r,
		S:        s,
	}
}

func NewCAEC(d, x, y *big.Int, curveType dlog.Curve) *CAEC {
	c := dlog.GetEllipticCurve(curveType)
	pubKey := ecdsa.PublicKey{Curve: c, X: x, Y: y}
	privateKey := ecdsa.PrivateKey{PublicKey: pubKey, D: d}

	schnorrVerifier := dlogproofs.NewSchnorrECVerifier(curveType, types.Sigma)
	ca := CAEC{
		SchnorrVerifier: schnorrVerifier,
		privateKey:      &privateKey,
	}

	return &ca
}

func (ca *CAEC) GetChallenge(a, b, x *types.ECGroupElement) *big.Int {
	// TODO: check if b is really a valuable external user's public master key; if not, close the session

	ca.a = a
	ca.b = b
	ca.SchnorrVerifier.SetProofRandomData(x, a, b)
	challenge, _ := ca.SchnorrVerifier.GetChallenge()
	return challenge
}

func (ca *CAEC) Verify(z *big.Int) (*CACertificateEC, error) {
	verified := ca.SchnorrVerifier.Verify(z, nil)
	if verified {
		r := common.GetRandomInt(ca.SchnorrVerifier.DLog.OrderOfSubgroup)
		blindedA1, blindedA2 := ca.SchnorrVerifier.DLog.Exponentiate(ca.a.X, ca.a.Y, r)
		blindedB1, blindedB2 := ca.SchnorrVerifier.DLog.Exponentiate(ca.b.X, ca.b.Y, r)
		// blindedA, blindedB must be used only once (never use the same pair for two
		// different organizations)

		hashed := common.HashIntoBytes(blindedA1, blindedA2, blindedB1, blindedB2)
		r, s, err := ecdsa.Sign(rand.Reader, ca.privateKey, hashed)
		if err != nil {
			return nil, err
		} else {
			blindedA := types.NewECGroupElement(blindedA1, blindedA2)
			blindedB := types.NewECGroupElement(blindedB1, blindedB2)
			return NewCACertificateEC(blindedA, blindedB, r, s), nil
		}
	} else {
		return nil, fmt.Errorf("The knowledge of secret was not verified.")
	}
}
