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

package compatibility

import (
	"math/big"

	"fmt"

	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
)

// Pseudonym represents an equivalent of pseudonymsys.Pseudonym, but has string
// field types to overcome type restrictions of Go language binding tools.
type Pseudonym struct {
	A string
	B string
}

func NewPseudonym(a, b string) *Pseudonym {
	return &Pseudonym{
		A: a,
		B: b,
	}
}

// getNativeType translates compatibility Pseudonym to emmy's native pseudonymsys.Pseudonym.
func (p *Pseudonym) getNativeType() (*pseudonymsys.Pseudonym, error) {
	a, aOk := new(big.Int).SetString(p.A, 10)
	b, bOk := new(big.Int).SetString(p.B, 10)
	if !aOk || !bOk {
		return nil, fmt.Errorf("nym.A or nym.B: %s", ArgsConversionError)
	}

	pseudonym := pseudonymsys.NewPseudonym(a, b)
	return pseudonym, nil
}

// CACertificate represents an equivalent of pseudonymsys.CACertificate, but has string
// field types to overcome type restrictions of Go language binding tools.
type CACertificate struct {
	BlindedA string
	BlindedB string
	R        string
	S        string
}

func NewCACertificate(blindedA, blindedB, r, s string) *CACertificate {
	return &CACertificate{
		BlindedA: blindedA,
		BlindedB: blindedB,
		R:        r,
		S:        s,
	}
}

func (c *CACertificate) toNativeType() (*pseudonymsys.CACertificate, error) {
	blindedA, blindedAOk := new(big.Int).SetString(c.BlindedA, 10)
	blindedB, blindedBOk := new(big.Int).SetString(c.BlindedB, 10)
	r, rOk := new(big.Int).SetString(c.R, 10)
	s, sOk := new(big.Int).SetString(c.S, 10)
	if !blindedAOk || !blindedBOk || !rOk || !sOk {
		return nil, fmt.Errorf("certificate's blindedA, blindedB, r or s: %s",
			ArgsConversionError)
	}

	certificate := pseudonymsys.NewCACertificate(blindedA, blindedB, r, s)
	return certificate, nil
}

// PseudonymsysCAClient wraps around client.PseudonymsysCAClient to conform to
// type restrictions of Go language binding tools. It exposes the same set of methods as
// client.PseudonymsysCAClient.
type PseudonymsysCAClient struct {
	*client.PseudonymsysCAClient
}

func NewPseudonymsysCAClient(conn *Connection) (*PseudonymsysCAClient, error) {
	c, err := client.NewPseudonymsysCAClient(conn.ClientConn)
	if err != nil {
		return nil, err
	}

	return &PseudonymsysCAClient{
		PseudonymsysCAClient: c,
	}, nil
}

func (c *PseudonymsysCAClient) GenerateMasterNym(secret string) (*Pseudonym, error) {
	// Translate secret
	s, sOk := new(big.Int).SetString(secret, 10)
	if !sOk {
		return nil, fmt.Errorf("secret (%s): %s", secret, ArgsConversionError)
	}
	masterNym := c.PseudonymsysCAClient.GenerateMasterNym(s)
	return NewPseudonym(masterNym.A.String(), masterNym.B.String()), nil
}

func (c *PseudonymsysCAClient) GenerateCertificate(userSecret string,
	nym *Pseudonym) (*CACertificate, error) {
	// Translate secret
	secret, secretOk := new(big.Int).SetString(userSecret, 10)
	if !secretOk {
		return nil, fmt.Errorf("secret (%s): %s", secret, ArgsConversionError)
	}

	// Translate Pseudonym
	pseudonym, err := nym.getNativeType()
	if err != nil {
		return nil, err
	}

	// Call PseudonymsysCAClient client with translated parameters
	cert, err := c.PseudonymsysCAClient.GenerateCertificate(secret, pseudonym)
	if err != nil {
		return nil, err
	}

	return NewCACertificate(
		cert.BlindedA.String(),
		cert.BlindedB.String(),
		cert.R.String(),
		cert.S.String()), nil
}
