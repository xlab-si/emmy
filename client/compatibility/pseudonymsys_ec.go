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
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
)

// OrgPubKeysEC represents an equivalent of pseudonymsys.OrgPubKeysEC,
// but has field types compatible with Go language binding tools.
type OrgPubKeysEC struct {
	H1 *ECGroupElement
	H2 *ECGroupElement
}

func NewOrgPubKeysEC(h1, h2 *ECGroupElement) *OrgPubKeysEC {
	return &OrgPubKeysEC{
		H1: h1,
		H2: h2,
	}
}

// getNativeType translates compatibility OrgPubKeysEC to emmy's native pseudonymsys.OrgPubKeysEC.
func (k *OrgPubKeysEC) getNativeType() (*pseudonymsys.OrgPubKeysEC, error) {
	h1, err := k.H1.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("pubKeys.H1: %s", err)
	}
	h2, err := k.H2.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("pubKeys.H2: %s", err)
	}

	orgPubKeys := pseudonymsys.NewOrgPubKeysEC(h1, h2)
	return orgPubKeys, nil
}

// TranscriptEC represents an equivalent of dlogproofs.TranscriptEC, but has string
// field types to overcome type restrictions of Go language binding tools.
type TranscriptEC struct {
	Alpha_1 string
	Alpha_2 string
	Beta_1  string
	Beta_2  string
	Hash    string
	ZAlpha  string
}

func NewTranscriptEC(alpha_1, alpha_2, beta_1, beta_2, hash, zAlpha string) *TranscriptEC {
	return &TranscriptEC{
		Alpha_1: alpha_1,
		Alpha_2: alpha_2,
		Beta_1:  beta_1,
		Beta_2:  beta_2,
		Hash:    hash,
		ZAlpha:  zAlpha,
	}
}

// getNativeType translates compatibility TranscriptEC to emmy's native dlogproofs.TranscriptEC.
func (t *TranscriptEC) getNativeType() (*dlogproofs.TranscriptEC, error) {
	alpha1, alpha1Ok := new(big.Int).SetString(t.Alpha_1, 10)
	alpha2, alpha2Ok := new(big.Int).SetString(t.Alpha_2, 10)
	beta1, beta1Ok := new(big.Int).SetString(t.Beta_1, 10)
	beta2, beta2Ok := new(big.Int).SetString(t.Beta_2, 10)
	hash, hashOk := new(big.Int).SetString(t.Hash, 10)
	zAlpha, zAlphaOk := new(big.Int).SetString(t.ZAlpha, 10)

	if !alpha1Ok || !alpha2Ok || !beta1Ok || !beta2Ok || !hashOk || !zAlphaOk {
		return nil, ArgsConversionError
	}

	transcript := dlogproofs.NewTranscriptEC(alpha1, alpha2, beta1, beta2, hash, zAlpha)
	return transcript, nil
}

// CredentialEC represents an equivalent of pseudonymsys.CredentialEC,
// but has field types compatible with Go language binding tools.
type CredentialEC struct {
	SmallAToGamma *ECGroupElement
	SmallBToGamma *ECGroupElement
	AToGamma      *ECGroupElement
	BToGamma      *ECGroupElement
	T1            *TranscriptEC
	T2            *TranscriptEC
}

func NewCredentialEC(aToGamma, bToGamma, AToGamma, BToGamma *ECGroupElement,
	t1, t2 *TranscriptEC) *CredentialEC {
	return &CredentialEC{
		SmallAToGamma: aToGamma,
		SmallBToGamma: bToGamma,
		AToGamma:      AToGamma,
		BToGamma:      BToGamma,
		T1:            t1,
		T2:            t2,
	}
}

// getNativeType translates compatibility CredentialEC to emmy's native pseudonymsys.CredentialEC.
func (c *CredentialEC) getNativeType() (*pseudonymsys.CredentialEC, error) {
	aTg, err := c.SmallAToGamma.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("credential.SmallAToGamma: %s", err)
	}
	bTg, err := c.SmallBToGamma.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("credential.SmallBToGamma: %s", err)
	}

	ATg, err := c.AToGamma.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("credential.AToGamma: %s", err)
	}

	BTg, err := c.BToGamma.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("credential.BToGamma: %s", err)
	}

	t1, err := c.T1.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("credential.T1: %s", err)
	}

	t2, err := c.T2.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("credential.T2: %s", err)
	}
	cred := pseudonymsys.NewCredentialEC(aTg, bTg, ATg, BTg, t1, t2)
	return cred, nil
}

// PseudonymsysClientEC wraps around client.PseudonymsysClientEC to conform to
// type restrictions of Go language binding tools. It exposes the same set of methods as
// client.PseudonymsysClientEC.
type PseudonymsysClientEC struct {
	*client.PseudonymsysClientEC
}

func NewPseudonymsysClientEC(conn *Connection, curve int) (*PseudonymsysClientEC, error) {
	c, err := client.NewPseudonymsysClientEC(conn.ClientConn, groups.ECurve(curve))
	if err != nil {
		return nil, err
	}

	return &PseudonymsysClientEC{
		PseudonymsysClientEC: c,
	}, nil
}

// GenerateMasterKey returns a string representation of the master secret key
// to be used with the pseudonym system scheme in the EC arithmetic.
func (c *PseudonymsysClientEC) GenerateMasterKey() string {
	return c.PseudonymsysClientEC.GenerateMasterKey().String()
}

func (c *PseudonymsysClientEC) GenerateNym(userSecret string,
	cert *CACertificateEC, regKey string) (*PseudonymEC, error) {
	// Translate secret
	secret, secretOk := new(big.Int).SetString(userSecret, 10)
	if !secretOk {
		return nil, fmt.Errorf("secret (%s): %s", secret, ArgsConversionError)
	}

	// Translate CACertificateEC
	certificate, err := cert.getNativeType()
	if err != nil {
		return nil, err
	}

	// Call PseudonymsysClientEC client with translated parameters
	nym, err := c.PseudonymsysClientEC.GenerateNym(secret, certificate, regKey)
	if err != nil {
		return nil, err
	}

	// Translate from native emmy types to compatibility types
	a := NewECGroupElement(nym.A.X.String(), nym.A.Y.String())
	b := NewECGroupElement(nym.B.X.String(), nym.B.Y.String())
	return NewPseudonymEC(a, b), nil
}

func (c *PseudonymsysClientEC) ObtainCredential(userSecret string,
	nym *PseudonymEC, pubKeys *OrgPubKeysEC) (*CredentialEC, error) {
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

	// Translate OrgPubKeysEC
	orgPubKeys, err := pubKeys.getNativeType()
	if err != nil {
		return nil, err
	}

	// Call PseudonymsysClientEC client with translated parameters
	credential, err := c.PseudonymsysClientEC.ObtainCredential(secret, pseudonym, orgPubKeys)
	if err != nil {
		return nil, err
	}

	// Translate from native emmy types to compatibility types
	t1 := NewTranscriptEC(
		credential.T1.Alpha_1.String(),
		credential.T1.Alpha_2.String(),
		credential.T1.Beta_1.String(),
		credential.T1.Beta_2.String(),
		credential.T1.Hash.String(),
		credential.T1.ZAlpha.String())
	t2 := NewTranscriptEC(
		credential.T2.Alpha_1.String(),
		credential.T2.Alpha_2.String(),
		credential.T2.Beta_1.String(),
		credential.T2.Beta_2.String(),
		credential.T2.Hash.String(),
		credential.T2.ZAlpha.String())
	smallAToGamma := NewECGroupElement(
		credential.SmallAToGamma.X.String(),
		credential.SmallAToGamma.Y.String(),
	)
	smallBToGamma := NewECGroupElement(
		credential.SmallBToGamma.X.String(),
		credential.SmallBToGamma.Y.String(),
	)
	aToGamma := NewECGroupElement(
		credential.AToGamma.X.String(),
		credential.AToGamma.Y.String(),
	)
	bToGamma := NewECGroupElement(
		credential.BToGamma.X.String(),
		credential.BToGamma.Y.String(),
	)

	return NewCredentialEC(smallAToGamma, smallBToGamma, aToGamma, bToGamma, t1, t2), nil
}

func (c *PseudonymsysClientEC) TransferCredential(orgName, userSecret string,
	nym *PseudonymEC, cred *CredentialEC) (string, error) {
	// Translate secret
	secret, secretOk := new(big.Int).SetString(userSecret, 10)
	if !secretOk {
		return "", fmt.Errorf("secret (%s): %s", secret, ArgsConversionError)
	}

	// Translate PseudonymEC
	pseudonym, err := nym.getNativeType()
	if err != nil {
		return "", err
	}

	// Translate CredentialEC
	credential, err := cred.getNativeType()
	if err != nil {
		return "", err
	}

	// Call PseudonymsysClientEC client with translated parameters
	sessionKey, err := c.PseudonymsysClientEC.TransferCredential(orgName, secret, pseudonym,
		credential)
	if err != nil {
		return "", err
	}

	return sessionKey.Value, nil
}
