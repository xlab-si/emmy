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
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
)

// Credential represents an equivalent of pseudonymsys.Credential,
// but has field types compatible with Go language binding tools.
type Credential struct {
	SmallAToGamma string
	SmallBToGamma string
	AToGamma      string
	BToGamma      string
	T1            *Transcript
	T2            *Transcript
}

func NewCredential(aToGamma, bToGamma, AToGamma, BToGamma string,
	t1, t2 *Transcript) *Credential {
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

// getNativeType translates compatibility Credential to emmy's native pseudonymsys.Credential.
func (c *Credential) getNativeType() (*pseudonymsys.Credential, error) {
	atG, atGOk := new(big.Int).SetString(c.SmallAToGamma, 10)
	btG, btGOk := new(big.Int).SetString(c.SmallBToGamma, 10)
	AtG, AtGOk := new(big.Int).SetString(c.AToGamma, 10)
	BtG, BtGOk := new(big.Int).SetString(c.BToGamma, 10)
	if !atGOk || !btGOk || !AtGOk || !BtGOk {
		return nil, ArgsConversionError
	}
	t1, err := c.T1.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("credential.T1: %s", err)
	}
	t2, err := c.T2.getNativeType()
	if err != nil {
		return nil, fmt.Errorf("credential.T2: %s", err)
	}

	cred := pseudonymsys.NewCredential(atG, btG, AtG, BtG, t1, t2)
	return cred, nil
}

// OrgPubKeys represents an equivalent of pseudonymsys.PubKey, but has string
// field types to overcome type restrictions of Go language binding tools.
type OrgPubKeys struct {
	H1 string
	H2 string
}

func NewOrgPubKeys(h1, h2 string) *OrgPubKeys {
	return &OrgPubKeys{
		H1: h1,
		H2: h2,
	}
}

// getNativeType translates compatibility OrgPubKeys to emmy's native pseudonymsys.PubKey.
func (k *OrgPubKeys) getNativeType() (*pseudonymsys.PubKey, error) {
	h1, h1Ok := new(big.Int).SetString(k.H1, 10)
	h2, h2Ok := new(big.Int).SetString(k.H2, 10)
	if !h1Ok || !h2Ok {
		return nil, fmt.Errorf("pubKeys.h1 or pubKeys.h2: %s", ArgsConversionError)
	}

	orgPubKeys := pseudonymsys.NewPubKey(h1, h2)
	return orgPubKeys, nil
}

// Transcript represents an equivalent of dlogproofs.Transcript, but has string
// field types to overcome type restrictions of Go language binding tools.
type Transcript struct {
	A      string
	B      string
	Hash   string
	ZAlpha string
}

func NewTranscript(a, b, hash, zAlpha string) *Transcript {
	return &Transcript{
		A:      a,
		B:      b,
		Hash:   hash,
		ZAlpha: zAlpha,
	}
}

// getNativeType translates compatibility Transcript to emmy's native dlogproofs.Transcript.
func (t *Transcript) getNativeType() (*dlogproofs.Transcript, error) {
	a, aOk := new(big.Int).SetString(t.A, 10)
	b, bOk := new(big.Int).SetString(t.B, 10)
	hash, hashOk := new(big.Int).SetString(t.Hash, 10)
	zAlpha, zAlphaOk := new(big.Int).SetString(t.ZAlpha, 10)
	if !aOk || !bOk || !hashOk || !zAlphaOk {
		return nil, fmt.Errorf("transcript's a, b, hash or zAlpha: %s", ArgsConversionError)
	}

	transcript := dlogproofs.NewTranscript(a, b, hash, zAlpha)
	return transcript, nil
}

// PseudonymsysClient wraps around client.PseudonymsysClient to conform to
// type restrictions of Go language binding tools. It exposes the same set of methods as
// client.PseudonymsysClient.
type PseudonymsysClient struct {
	*client.PseudonymsysClient
}

func NewPseudonymsysClient(conn *Connection, g *SchnorrGroup) (*PseudonymsysClient, error) {
	// Translate SchnorrGroup
	group, err := g.toNativeType()
	if err != nil {
		return nil, err
	}

	c, err := client.NewPseudonymsysClient(conn.ClientConn, group)
	if err != nil {
		return nil, err
	}

	return &PseudonymsysClient{
		PseudonymsysClient: c,
	}, nil
}

// GenerateMasterKey returns a string representation of the master secret key
// to be used with the pseudonym system scheme.
func (c *PseudonymsysClient) GenerateMasterKey() string {
	return c.PseudonymsysClient.GenerateMasterKey().String()
}

func (c *PseudonymsysClient) GenerateNym(userSecret string,
	cert *CACertificate, regKey string) (*Pseudonym, error) {
	// Translate secret
	secret, secretOk := new(big.Int).SetString(userSecret, 10)
	if !secretOk {
		return nil, fmt.Errorf("secret (%s): %s", secret, ArgsConversionError)
	}

	// Translate CACertificate
	certificate, err := cert.toNativeType()
	if err != nil {
		return nil, err
	}

	// Call PseudonymsysClient client with translated parameters
	nym, err := c.PseudonymsysClient.GenerateNym(secret, certificate, regKey)
	if err != nil {
		return nil, err
	}

	// Translate from native emmy types to compatibility types
	pseudonym := NewPseudonym(nym.A.String(), nym.B.String())

	return pseudonym, nil
}

func (c *PseudonymsysClient) ObtainCredential(userSecret string,
	nym *Pseudonym, pubKeys *OrgPubKeys) (*Credential, error) {
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

	// Translate OrgPubKeys
	orgPubKeys, err := pubKeys.getNativeType()
	if err != nil {
		return nil, err
	}

	// Call PseudonymsysClient client with translated parameters
	credential, err := c.PseudonymsysClient.ObtainCredential(secret, pseudonym, orgPubKeys)
	if err != nil {
		return nil, err
	}

	// Translate from native emmy types to compatibility types
	t1 := NewTranscript(
		credential.T1.A.String(),
		credential.T1.B.String(),
		credential.T1.Hash.String(),
		credential.T1.ZAlpha.String())
	t2 := NewTranscript(
		credential.T2.A.String(),
		credential.T2.B.String(),
		credential.T2.Hash.String(),
		credential.T2.ZAlpha.String())

	return NewCredential(
		credential.SmallAToGamma.String(),
		credential.SmallBToGamma.String(),
		credential.AToGamma.String(),
		credential.BToGamma.String(),
		t1,
		t2), nil
}

func (c *PseudonymsysClient) TransferCredential(orgName, userSecret string,
	nym *Pseudonym, cred *Credential) (string, error) {
	// Translate secret
	secret, secretOk := new(big.Int).SetString(userSecret, 10)
	if !secretOk {
		return "", fmt.Errorf("secret (%s): %s", secret, ArgsConversionError)
	}

	// Translate Pseudonym
	pseudonym, err := nym.getNativeType()
	if err != nil {
		return "", err
	}

	// Translate Credential
	credential, err := cred.getNativeType()
	if err != nil {
		return "", err
	}

	// Call PseudonymsysClient client with translated parameters
	sessionKey, err := c.PseudonymsysClient.TransferCredential(orgName, secret, pseudonym,
		credential)
	if err != nil {
		return "", err
	}

	return sessionKey.Value, nil
}
