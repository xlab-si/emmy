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

type CA struct {
	SchnorrVerifier *dlogproofs.SchnorrVerifier
	a               *big.Int
	b               *big.Int
	privateKey      *ecdsa.PrivateKey
}

type CACertificate struct {
	BlindedA *big.Int
	BlindedB *big.Int
	R        *big.Int
	S        *big.Int
}

func NewCACertificate(blindedA, blindedB, r, s *big.Int) *CACertificate {
	return &CACertificate{
		BlindedA: blindedA,
		BlindedB: blindedB,
		R:        r,
		S:        s,
	}
}

func NewCA(zpdlog *dlog.ZpDLog, d, x, y *big.Int) *CA {
	c := dlog.GetEllipticCurve(dlog.P256)
	pubKey := ecdsa.PublicKey{Curve: c, X: x, Y: y}
	privateKey := ecdsa.PrivateKey{PublicKey: pubKey, D: d}

	schnorrVerifier := dlogproofs.NewSchnorrVerifier(zpdlog, types.Sigma)
	ca := CA{
		SchnorrVerifier: schnorrVerifier,
		privateKey:      &privateKey,
	}

	return &ca
}

func (ca *CA) GetChallenge(a, b, x *big.Int) *big.Int {
	// TODO: check if b is really a valuable external user's public master key; if not, close the session

	ca.a = a
	ca.b = b
	ca.SchnorrVerifier.SetProofRandomData(x, a, b)
	challenge, _ := ca.SchnorrVerifier.GetChallenge()
	return challenge
}

func (ca *CA) Verify(z *big.Int) (*CACertificate, error) {
	verified := ca.SchnorrVerifier.Verify(z, nil)
	if verified {
		r := common.GetRandomInt(ca.SchnorrVerifier.DLog.OrderOfSubgroup)
		blindedA, _ := ca.SchnorrVerifier.DLog.Exponentiate(ca.a, r)
		blindedB, _ := ca.SchnorrVerifier.DLog.Exponentiate(ca.b, r)
		// blindedA, blindedB must be used only once (never use the same pair for two
		// different organizations)

		hashed := common.HashIntoBytes(blindedA, blindedB)
		r, s, err := ecdsa.Sign(rand.Reader, ca.privateKey, hashed)
		if err != nil {
			return nil, err
		} else {
			return NewCACertificate(blindedA, blindedB, r, s), nil
		}
	} else {
		return nil, fmt.Errorf("The knowledge of secret was not verified.")
	}
}
