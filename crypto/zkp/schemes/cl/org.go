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

package cl

import (
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
)

type PubKey struct {
	N           *big.Int
	S           *big.Int
	Z           *big.Int
	RsKnown     []*big.Int // one R corresponds to one attribute - these attributes are known to both - receiver and issuer
	RsCommitted []*big.Int // issuer knows only commitments of these attributes
	RsHidden    []*big.Int // only receiver knows these attributes
	// the fields below are for commitments of the (committed) attributes
	N1 *big.Int
	G  *big.Int
	H  *big.Int
}

func NewPubKey(N *big.Int, S, Z *big.Int, RsKnown, RsCommitted, RsHidden []*big.Int, N1, G, H *big.Int) *PubKey {
	return &PubKey{
		N:           N,
		S:           S,
		Z:           Z,
		RsKnown:     RsKnown,
		RsCommitted: RsCommitted,
		RsHidden:    RsHidden,
		N1:          N1,
		G:           G,
		H:           H,
	}
}

// GetContext concatenates public parameters and returns a corresponding number.
func (k *PubKey) GetContext() *big.Int {
	numbers := []*big.Int{k.N, k.S, k.Z}
	numbers = append(numbers, k.RsKnown...)
	numbers = append(numbers, k.RsCommitted...)
	numbers = append(numbers, k.RsHidden...)
	concatenated := common.ConcatenateNumbers(numbers...)
	return new(big.Int).SetBytes(concatenated)
}

type Org struct {
	Params                     *Params
	Group                      *groups.QRSpecialRSA
	PedersenReceiver           *commitments.PedersenReceiver
	PubKey                     *PubKey
	attributesSpecialRSAPrimes *common.SpecialRSAPrimes
	credentialIssuer           *OrgCredentialIssuer
	credentialIssueNonceOrg    *big.Int
	proveCredentialNonceOrg    *big.Int
	receiverRecords            map[*big.Int]*ReceiverRecord // contains a record for each credential - needed for update credential; TODO: use some DB
}

func NewOrg(name string, clParamSizes *Params) (*Org, error) {
	group, err := groups.NewQRSpecialRSA(clParamSizes.NLength / 2)
	if err != nil {
		return nil, fmt.Errorf("error when creating QRSpecialRSA group: %s", err)
	}

	S, Z, RsKnown, RsCommitted, RsHidden, err := generateQuadraticResidues(group, clParamSizes.KnownAttrsNum,
		clParamSizes.CommittedAttrsNum, clParamSizes.HiddenAttrsNum)

	// for commitments of (committed) attributes:
	commitmentReceiver, err := commitments.NewDamgardFujisakiReceiver(clParamSizes.NLength/2, clParamSizes.SecParam)
	if err != nil {
		return nil, fmt.Errorf("error when creating DF commitment receiver: %s", err)
	}

	pubKey := NewPubKey(group.N, S, Z, RsKnown, RsCommitted, RsHidden, commitmentReceiver.QRSpecialRSA.N,
		commitmentReceiver.G, commitmentReceiver.H)
	if err != nil {
		return nil, fmt.Errorf("error when creating QRSpecialRSA group: %s", err)
	}

	pedersenParams, err := commitments.GeneratePedersenParams(clParamSizes.RhoBitLen)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen receiver: %s", err)
	}

	return NewOrgFromParams(name, clParamSizes, group.GetSpecialRSAPrimes(), pubKey, pedersenParams,
		commitmentReceiver.QRSpecialRSA.GetSpecialRSAPrimes(), commitmentReceiver.G, commitmentReceiver.H)
}

func NewOrgFromParams(name string, clParamSizes *Params, primes *common.SpecialRSAPrimes,
	pubKey *PubKey, pedersenParams *commitments.PedersenParams,
	attributesSpecialRSAPrimes *common.SpecialRSAPrimes, G, H *big.Int) (*Org, error) {
	group, err := groups.NewQRSpecialRSAFromParams(primes)
	if err != nil {
		return nil, fmt.Errorf("error when creating QRSpecialRSA group: %s", err)
	}

	return &Org{
		Params:                     clParamSizes,
		Group:                      group,
		PubKey:                     pubKey,
		PedersenReceiver:           commitments.NewPedersenReceiverFromParams(pedersenParams),
		attributesSpecialRSAPrimes: attributesSpecialRSAPrimes,
		receiverRecords:            make(map[*big.Int]*ReceiverRecord), // TODO: will be replaced with DB
	}, nil
}

func (o *Org) getNonce() *big.Int {
	secParam := big.NewInt(int64(o.Params.SecParam))
	b := new(big.Int).Exp(big.NewInt(2), secParam, nil)

	return common.GetRandomInt(b)
}

func (o *Org) GetCredentialIssueNonce() *big.Int {
	nonce := o.getNonce()
	o.credentialIssueNonceOrg = nonce

	return nonce
}

func (o *Org) VerifyCredentialRequest(nym *big.Int, knownAttrs, commitmentsOfAttrs []*big.Int,
	cr *CredentialRequest) (bool, error) {
	credentialIssuer, err := NewOrgCredentialIssuer(o, nym, knownAttrs, commitmentsOfAttrs)
	if err != nil {
		return false, fmt.Errorf("error when creating credential issuer: %v", err)
	}
	o.credentialIssuer = credentialIssuer

	return o.credentialIssuer.VerifyCredentialRequest(cr), nil
}

func (o *Org) IssueCredential(nonceUser *big.Int) (*Credential,
	*qrspecialrsaproofs.RepresentationProof) {
	return o.credentialIssuer.IssueCredential(nonceUser)
}

func (o *Org) UpdateCredential(nonceUser *big.Int, newKnownAttrs []*big.Int) (*Credential,
	*qrspecialrsaproofs.RepresentationProof) {
	return o.credentialIssuer.UpdateCredential(nonceUser, newKnownAttrs)
}

func (o *Org) GetProveCredentialNonce() *big.Int {
	nonce := o.getNonce()
	o.proveCredentialNonceOrg = nonce

	return nonce
}

func (o *Org) ProveCredential(A *big.Int, proof *qrspecialrsaproofs.RepresentationProof,
	knownAttrs []*big.Int) (bool, error) {
	ver := qrspecialrsaproofs.NewRepresentationVerifier(o.Group, o.Params.SecParam)
	bases := append(o.PubKey.RsHidden, A)
	bases = append(bases, o.PubKey.S)

	denom := big.NewInt(1)
	for i := 0; i < len(knownAttrs); i++ {
		t1 := o.Group.Exp(o.PubKey.RsKnown[i], knownAttrs[i])
		denom = o.Group.Mul(denom, t1)
	}

	for i := 0; i < len(o.credentialIssuer.commitmentsOfAttrs); i++ {
		t1 := o.Group.Exp(o.PubKey.RsCommitted[i], o.credentialIssuer.commitmentsOfAttrs[i])
		denom = o.Group.Mul(denom, t1)
	}
	denomInv := o.Group.Inv(denom)
	y := o.Group.Mul(o.PubKey.Z, denomInv)
	ver.SetProofRandomData(proof.ProofRandomData, bases, y)

	context := o.PubKey.GetContext()
	l := []*big.Int{context, proof.ProofRandomData, o.proveCredentialNonceOrg}
	//l = append(l, ...) // TODO: add other values

	c := common.Hash(l...) // TODO: function for GetChallenge
	if proof.Challenge.Cmp(c) != 0 {
		return false, fmt.Errorf("challenge is not correct")
	}

	ver.SetChallenge(proof.Challenge)

	return ver.Verify(proof.ProofData), nil
}

type ReceiverRecord struct {
	KnownAttrs []*big.Int
	Q          *big.Int
	V11        *big.Int
	Context    *big.Int
}

// Returns ReceiverRecord which contains user data needed when updating the credential for this user.
func NewReceiverRecord(knownAttrs []*big.Int, Q, v11, context *big.Int) *ReceiverRecord {
	return &ReceiverRecord{
		KnownAttrs: knownAttrs,
		Q:          Q,
		V11:        v11,
		Context:    context,
	}
}

type Credential struct {
	A   *big.Int
	e   *big.Int
	v11 *big.Int
}

func NewCredential(A, e, v11 *big.Int) *Credential {
	return &Credential{
		A:   A,
		e:   e,
		v11: v11,
	}
}

func generateQuadraticResidues(group *groups.QRSpecialRSA, knownAttrsNum, committedAttrsNum,
	hiddenAttrsNum int) (*big.Int, *big.Int, []*big.Int,
	[]*big.Int, []*big.Int, error) {
	S, err := group.GetRandomGenerator()
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("error when searching for QRSpecialRSA generator: %s", err)
	}
	Z := group.Exp(S, common.GetRandomInt(group.Order))

	RsKnown := make([]*big.Int, knownAttrsNum)
	for i, _ := range RsKnown {
		RsKnown[i] = group.Exp(S, common.GetRandomInt(group.Order))
	}

	RsCommitted := make([]*big.Int, committedAttrsNum)
	for i, _ := range RsCommitted {
		RsCommitted[i] = group.Exp(S, common.GetRandomInt(group.Order))
	}

	RsHidden := make([]*big.Int, hiddenAttrsNum)
	for i, _ := range RsHidden {
		RsHidden[i] = group.Exp(S, common.GetRandomInt(group.Order))
	}

	return S, Z, RsKnown, RsCommitted, RsHidden, nil
}
