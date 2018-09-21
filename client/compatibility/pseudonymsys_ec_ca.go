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
	"github.com/xlab-si/emmy/crypto/ec"
	"github.com/xlab-si/emmy/crypto/ecpseudsys"
)

// Representations of specific elliptic curves to be used in elliptic cryptography based schemes.
const (
	P256 = int(ec.P256)
	P224 = int(ec.P224)
	P384 = int(ec.P384)
	P521 = int(ec.P521)
)

// ECGroupElement represents an equivalent of ec.GroupElement, but has string
// field types to overcome type restrictions of Go language binding tools.
type ECGroupElement struct {
	X string
	Y string
}

func NewECGroupElement(x, y string) *ECGroupElement {
	return &ECGroupElement{
		X: x,
		Y: y,
	}
}

// getNativeType translates compatibility ECGroupElement to emmy's native ec.GroupElement.
func (e *ECGroupElement) getNativeType() (*ec.GroupElement, error) {
	x, xOk := new(big.Int).SetString(e.X, 10)
	y, yOk := new(big.Int).SetString(e.Y, 10)

	if !xOk || !yOk {
		return nil, ArgsConversionError
	}

	ecGroupEl := ec.NewGroupElement(x, y)
	return ecGroupEl, nil
}

// PseudonymEC represents an equivalent of pseudonymsys.PseudonymEC,
// but has field types compatible with Go language binding tools.
type PseudonymEC struct {
	A *ECGroupElement
	B *ECGroupElement
}

func NewPseudonymEC(a, b *ECGroupElement) *PseudonymEC {
	return &PseudonymEC{
		A: a,
		B: b,
	}
}

// getNativeType translates compatibility PseudonymEC to emmy's native pseudonymsys.PseudonymEC.
func (p *PseudonymEC) getNativeType() (*ecpseudsys.Nym, error) {
	a, err := p.A.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("nym.A: %s", ArgsConversionError)
	}
	b, err := p.B.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("nym.B: %s", ArgsConversionError)
	}
	pseudonym := ecpseudsys.NewNym(a, b)
	return pseudonym, nil
}

// CACertificateEC represents an equivalent of pseudonymsys.CACertificateEC,
// but has field types compatible with Go language binding tools.
type CACertificateEC struct {
	BlindedA *ECGroupElement
	BlindedB *ECGroupElement
	R        string
	S        string
}

func NewCACertificateEC(bA, bB *ECGroupElement, r, s string) *CACertificateEC {
	return &CACertificateEC{
		BlindedA: bA,
		BlindedB: bB,
		R:        r,
		S:        s,
	}
}

// getNativeType translates compatibility CACertificateEC to emmy's native pseudonymsys.CACertificateEC.
func (c *CACertificateEC) getNativeType() (*ecpseudsys.CACert, error) {
	blindedA, err := c.BlindedA.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("cert.BlindedA: %s", ArgsConversionError)
	}
	blindedB, err := c.BlindedB.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("cert.BlindedB: %s", ArgsConversionError)
	}
	r, rOk := new(big.Int).SetString(c.R, 10)
	if !rOk {
		return nil, fmt.Errorf("cert.R (%s): %s", c.R, ArgsConversionError)
	}
	s, sOk := new(big.Int).SetString(c.S, 10)
	if !sOk {
		return nil, fmt.Errorf("cert.S (%s): %s", c.S, ArgsConversionError)
	}
	certificate := ecpseudsys.NewCACert(blindedA, blindedB, r, s)
	return certificate, nil
}

// PseudonymsysCAECClient wraps around client.PseudonymsysCAClientEC to conform to
// type restrictions of Go language binding tools. It exposes the same set of methods as
// client.PseudonymsysCAClientEC.
type PseudonymsysCAClientEC struct {
	*client.PseudonymsysCAClientEC
}

func NewPseudonymsysCAClientEC(conn *Connection, curve int) (*PseudonymsysCAClientEC, error) {
	c, err := client.NewPseudonymsysCAClientEC(conn.ClientConn, ec.Curve(curve))
	if err != nil {
		return nil, err
	}

	return &PseudonymsysCAClientEC{
		PseudonymsysCAClientEC: c,
	}, nil
}

func (c *PseudonymsysCAClientEC) GenerateMasterNym(secret string, curve int) (*PseudonymEC,
	error) {
	// Translate secret
	s, sOk := new(big.Int).SetString(secret, 10)
	if !sOk {
		return nil, fmt.Errorf("secret (%s): %s", secret, ArgsConversionError)
	}

	// Call PseudonymsysCAClientEC client with translated parameters
	masterNym := c.PseudonymsysCAClientEC.GenerateMasterNym(s)

	// Translate from native emmy types to compatibility types
	a := NewECGroupElement(masterNym.A.X.String(), masterNym.A.Y.String())
	b := NewECGroupElement(masterNym.B.X.String(), masterNym.B.Y.String())
	return NewPseudonymEC(a, b), nil
}

func (c *PseudonymsysCAClientEC) GenerateCertificate(userSecret string,
	nym *PseudonymEC) (*CACertificateEC, error) {
	// Translate secret
	secret, secretOk := new(big.Int).SetString(userSecret, 10)
	if !secretOk {
		return nil, fmt.Errorf("secret (%s): %s", secret, ArgsConversionError)
	}

	// Translate PseudonymEC
	pseudonym, err := nym.getNativeType()
	if err != nil {
		return nil, err
	}

	// Call PseudonymsysCAClientEC client with translated parameters
	cert, err := c.PseudonymsysCAClientEC.GenerateCertificate(secret, pseudonym)
	if err != nil {
		return nil, err
	}

	// Translate from native emmy types to compatibility types
	return NewCACertificateEC(
		NewECGroupElement(cert.BlindedA.X.String(), cert.BlindedA.Y.String()),
		NewECGroupElement(cert.BlindedB.X.String(), cert.BlindedB.Y.String()),
		cert.R.String(),
		cert.S.String()), nil
}
