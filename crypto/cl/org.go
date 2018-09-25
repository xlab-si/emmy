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
	"encoding/json"
	"fmt"
	"math/big"

	"crypto/rand"
	"encoding/gob"
	"os"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/df"
	"github.com/xlab-si/emmy/crypto/pedersen"
	"github.com/xlab-si/emmy/crypto/qr"
	"github.com/xlab-si/emmy/crypto/schnorr"
)

type PubKey struct {
	N              *big.Int
	S              *big.Int
	Z              *big.Int
	RsKnown        []*big.Int // one R corresponds to one attribute - these attributes are known to both - receiver and issuer
	RsCommitted    []*big.Int // issuer knows only commitments of these attributes
	RsHidden       []*big.Int // only receiver knows these attributes
	PedersenParams *pedersen.Params
	// the fields below are for commitments of the (committed) attributes
	N1 *big.Int
	G  *big.Int
	H  *big.Int
}

// GenerateUserMasterSecret generates a secret key that needs to be encoded into every user's credential as a
// sharing prevention mechanism.
func (k *PubKey) GenerateUserMasterSecret() *big.Int {
	return common.GetRandomInt(k.PedersenParams.Group.Q)
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

type SecKey struct {
	RsaPrimes                  *qr.RSASpecialPrimes
	AttributesSpecialRSAPrimes *qr.RSASpecialPrimes
}

type Org struct {
	Params             *Params
	Group              *qr.RSASpecial     // in this group attributes will be used as exponents (basis is PubKey.Rs...)
	pedersenReceiver   *pedersen.Receiver // used for nyms (nym is Pedersen commitment)
	nym                *big.Int
	nymVerifier        *schnorr.Verifier
	U                  *big.Int
	UVerifier          *qr.RepresentationVerifier
	PubKey             *PubKey
	SecKey             *SecKey
	commitmentsOfAttrs []*big.Int
	knownAttrs         []*big.Int
	attrsVerifiers     []*df.OpeningVerifier // user proves the knowledge of commitment opening (committedAttrs)
	credIssueNonceOrg  *big.Int
	proveCredNonceOrg  *big.Int
}

func NewOrg(params *Params) (*Org, error) {
	group, err := qr.NewRSASpecial(params.NLength / 2)
	if err != nil {
		return nil, fmt.Errorf("error when creating RSASpecial group: %s", err)
	}

	S, Z, RsKnown, RsCommitted, RsHidden, err := generateQuadraticResidues(group, params.KnownAttrsNum,
		params.CommittedAttrsNum, params.HiddenAttrsNum)
	if err != nil {
		return nil, fmt.Errorf("error when creating quadratic residues: %s", err)
	}

	// for commitments of (committed) attributes:
	commitmentReceiver, err := df.NewReceiver(params.NLength/2, params.SecParam)
	if err != nil {
		return nil, fmt.Errorf("error when creating DF commitment receiver: %s", err)
	}

	pedersenParams, err := pedersen.GenerateParams(params.RhoBitLen)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen receiver: %s", err)
	}

	pubKey := &PubKey{
		N:              group.N,
		S:              S,
		Z:              Z,
		RsKnown:        RsKnown,
		RsCommitted:    RsCommitted,
		RsHidden:       RsHidden,
		PedersenParams: pedersenParams,
		N1:             commitmentReceiver.QRSpecialRSA.N,
		G:              commitmentReceiver.G,
		H:              commitmentReceiver.H,
	}

	secKey := &SecKey{
		RsaPrimes:                  group.GetPrimes(),
		AttributesSpecialRSAPrimes: commitmentReceiver.QRSpecialRSA.GetPrimes(),
	}

	return NewOrgFromParams(params, pubKey, secKey)
}

// FIXME
func NewOrgFromParams(params *Params, pubKey *PubKey, secKey *SecKey) (*Org, error) {
	var group *qr.RSASpecial
	var err error
	if secKey != nil {
		group, err = qr.NewRSASpecialFromParams(secKey.RsaPrimes)
		if err != nil {
			return nil, fmt.Errorf("error when creating RSASpecial group: %s", err)
		}
	} else {
		// ProveCL requires only pub key which means some organization can check the validity of
		// credential only using public key of the organization that issued a credential.
		group = qr.NewRSApecialPublic(pubKey.N)
	}

	pedersenReceiver := pedersen.NewReceiverFromParams(pubKey.PedersenParams)

	return &Org{
		Params:           params,
		PubKey:           pubKey,
		SecKey:           secKey,
		Group:            group,
		pedersenReceiver: pedersenReceiver,
	}, nil
}

// FIXME
func LoadOrg(orgName, secKeyPath, pubKeyPath string) (*Org, error) {
	pubKey := new(PubKey)
	ReadGob(pubKeyPath, pubKey)
	secKey := new(SecKey)
	ReadGob(secKeyPath, secKey)

	params := GetDefaultParamSizes()
	org, err := NewOrgFromParams(params, pubKey, secKey)
	if err != nil {
		return nil, fmt.Errorf("error when loading CL org: %v", err)
	}

	return org, nil
}

func (o *Org) GenNonce() *big.Int {
	secParam := big.NewInt(int64(o.Params.SecParam))
	b := new(big.Int).Exp(big.NewInt(2), secParam, nil)

	return common.GetRandomInt(b)
}

func (o *Org) genCredRandoms() (*big.Int, *big.Int) {
	exp := big.NewInt(int64(o.Params.EBitLen - 1))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	var e *big.Int
	for {
		er, _ := rand.Prime(rand.Reader, o.Params.E1BitLen-1)
		e = new(big.Int).Add(er, b)
		if e.ProbablyPrime(20) { // e needs to be prime
			break
		}
	}

	vr, _ := rand.Prime(rand.Reader, o.Params.VBitLen-1)
	exp = big.NewInt(int64(o.Params.VBitLen - 1))
	b = new(big.Int).Exp(big.NewInt(2), exp, nil)
	v11 := new(big.Int).Add(vr, b)

	return e, v11
}

func (o *Org) genAProof(nonceUser, context, eInv, Q, A *big.Int) *qr.RepresentationProof {
	prover := qr.NewRepresentationProver(o.Group, o.Params.SecParam,
		[]*big.Int{eInv}, []*big.Int{Q}, A)
	proofRandomData := prover.GetProofRandomData(true)
	// challenge = hash(context||Q||A||AProofRandomData||nonceUser)
	challenge := common.Hash(context, Q, A, proofRandomData, nonceUser)
	proofData := prover.GetProofData(challenge)

	return qr.NewRepresentationProof(proofRandomData, challenge, proofData)
}

type CredResult struct {
	Cred   *Cred
	AProof *qr.RepresentationProof
	Record *ReceiverRecord
}

func (o *Org) IssueCred(cr *CredRequest) (*CredResult, error) {
	o.nymVerifier = schnorr.NewVerifier(o.pedersenReceiver.Params.Group)
	o.UVerifier = qr.NewRepresentationVerifier(o.Group, o.Params.SecParam)

	o.nym = cr.Nym
	o.knownAttrs = cr.KnownAttrs
	err := o.setUpAttrVerifiers(cr.CommitmentsOfAttrs)
	if err != nil {
		return nil, err
	}
	o.U = cr.U

	if verified := o.verifyCredRequest(cr); !verified {
		return nil, fmt.Errorf("credential request not valid")
	}

	e, v11 := o.genCredRandoms()

	// denom = U * S^v11 * R_1^attr_1 * ... * R_j^attr_j where only attributes from knownAttrs and committedAttrs
	acc := big.NewInt(1)
	for ind := 0; ind < len(o.knownAttrs); ind++ {
		t1 := o.Group.Exp(o.PubKey.RsKnown[ind], o.knownAttrs[ind])
		acc = o.Group.Mul(acc, t1)
	}

	for ind := 0; ind < len(o.commitmentsOfAttrs); ind++ {
		t1 := o.Group.Exp(o.PubKey.RsCommitted[ind], o.commitmentsOfAttrs[ind])
		acc = o.Group.Mul(acc, t1)
	}

	t := o.Group.Exp(o.PubKey.S, v11) // s^v11
	denom := o.Group.Mul(t, o.U)      // U * s^v11
	denom = o.Group.Mul(denom, acc)   // U * s^v11 * acc
	denomInv := o.Group.Inv(denom)
	Q := o.Group.Mul(o.PubKey.Z, denomInv)

	phiN := new(big.Int).Mul(o.Group.P1, o.Group.Q1)
	eInv := new(big.Int).ModInverse(e, phiN)
	A := o.Group.Exp(Q, eInv)

	context := o.PubKey.GetContext()
	AProof := o.genAProof(cr.Nonce, context, eInv, Q, A) // nonceUser!

	res := &CredResult{
		Cred:   NewCred(A, e, v11),
		AProof: AProof,
		Record: NewReceiverRecord(o.knownAttrs, o.commitmentsOfAttrs, Q, v11, context),
	}

	return res, nil
}

func (o *Org) UpdateCred(nym *big.Int, rec *ReceiverRecord, nonceUser *big.Int, newKnownAttrs []*big.Int) (*CredResult, error) {
	if o.knownAttrs == nil { // for example when Org is instantiated and there is no call to IssueCred
		o.knownAttrs = newKnownAttrs
		o.setUpAttrVerifiers(rec.CommitmentsOfAttrs)
		o.nymVerifier = schnorr.NewVerifier(o.pedersenReceiver.Params.Group) // pubKey.Params.Group
		o.UVerifier = qr.NewRepresentationVerifier(o.Group, o.Params.SecParam)
	}

	e, v11 := o.genCredRandoms()
	v11Diff := new(big.Int).Sub(v11, rec.V11)

	acc := big.NewInt(1)
	for ind := 0; ind < len(o.knownAttrs); ind++ {
		t1 := o.Group.Exp(o.PubKey.RsKnown[ind],
			new(big.Int).Sub(newKnownAttrs[ind], rec.KnownAttrs[ind]))
		acc = o.Group.Mul(acc, t1)
	}
	t := o.Group.Exp(o.PubKey.S, v11Diff)
	denom := o.Group.Mul(acc, t)
	denomInv := o.Group.Inv(denom)
	newQ := o.Group.Mul(rec.Q, denomInv)

	phiN := new(big.Int).Mul(o.Group.P1, o.Group.Q1)
	eInv := new(big.Int).ModInverse(e, phiN)
	newA := o.Group.Exp(newQ, eInv)

	context := o.PubKey.GetContext()
	AProof := o.genAProof(nonceUser, context, eInv, newQ, newA)
	// currently commitmentsOfAttrs cannot be updated

	res := &CredResult{
		Cred:   NewCred(newA, e, v11),
		AProof: AProof,
		Record: NewReceiverRecord(newKnownAttrs, rec.CommitmentsOfAttrs, newQ, v11, context),
	}

	return res, nil
}

func (o *Org) GetProveCredNonce() *big.Int {
	nonce := o.GenNonce()
	o.proveCredNonceOrg = nonce

	return nonce
}

// ProveCred proves the possession of a valid credential and reveals only the attributes the user desires
// to reveal. Which knownAttrs and commitmentsOfAttrs are to be revealed are given by revealedKnownAttrsIndices and
// revealedCommitmentsOfAttrsIndices parameters. Parameters knownAttrs and commitmentsOfAttrs must contain only
// known attributes and commitments of attributes (of attributes for which only commitment is known) which are
// to be revealed to the organization.
func (o *Org) ProveCred(A *big.Int, proof *qr.RepresentationProof,
	revealedKnownAttrsIndices, revealedCommitmentsOfAttrsIndices []int,
	knownAttrs, commitmentsOfAttrs []*big.Int) (bool, error) {
	ver := qr.NewRepresentationVerifier(o.Group, o.Params.SecParam)
	bases := []*big.Int{}
	for i := 0; i < len(o.PubKey.RsKnown); i++ {
		if !common.Contains(revealedKnownAttrsIndices, i) {
			bases = append(bases, o.PubKey.RsKnown[i])
		}
	}
	for i := 0; i < len(o.PubKey.RsCommitted); i++ {
		if !common.Contains(revealedCommitmentsOfAttrsIndices, i) {
			bases = append(bases, o.PubKey.RsCommitted[i])
		}
	}
	bases = append(bases, o.PubKey.RsHidden...)
	bases = append(bases, A)
	bases = append(bases, o.PubKey.S)

	denom := big.NewInt(1)
	for i := 0; i < len(knownAttrs); i++ {
		rInd := revealedKnownAttrsIndices[i]
		t1 := o.Group.Exp(o.PubKey.RsKnown[rInd], knownAttrs[i])
		denom = o.Group.Mul(denom, t1)
	}

	for i := 0; i < len(commitmentsOfAttrs); i++ {
		rInd := revealedCommitmentsOfAttrsIndices[i]
		t1 := o.Group.Exp(o.PubKey.RsCommitted[rInd], commitmentsOfAttrs[i])
		denom = o.Group.Mul(denom, t1)
	}
	denomInv := o.Group.Inv(denom)
	y := o.Group.Mul(o.PubKey.Z, denomInv)
	ver.SetProofRandomData(proof.ProofRandomData, bases, y)

	context := o.PubKey.GetContext()
	l := []*big.Int{context, proof.ProofRandomData, o.proveCredNonceOrg}
	//l = append(l, ...) // TODO: add other values

	c := common.Hash(l...) // TODO: function for GetChallenge
	if proof.Challenge.Cmp(c) != 0 {
		return false, fmt.Errorf("challenge is not correct")
	}

	ver.SetChallenge(proof.Challenge)

	return ver.Verify(proof.ProofData), nil
}

// Cred represents anonymous credentials.
type Cred struct {
	A   *big.Int
	E   *big.Int
	V11 *big.Int
}

func NewCred(A, e, v11 *big.Int) *Cred {
	return &Cred{
		A:   A,
		E:   e,
		V11: v11,
	}
}

func generateQuadraticResidues(group *qr.RSASpecial, knownAttrsNum, committedAttrsNum,
	hiddenAttrsNum int) (*big.Int, *big.Int, []*big.Int,
	[]*big.Int, []*big.Int, error) {
	S, err := group.GetRandomGenerator()
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("error when searching for RSASpecial generator: %s", err)
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

func (o *Org) GetCredIssueNonce() *big.Int {
	nonce := o.GenNonce()
	o.credIssueNonceOrg = nonce

	return nonce
}

func (o *Org) verifyCredRequest(cr *CredRequest) bool {
	return o.verifyNym(cr.NymProof) &&
		o.verifyU(cr.UProof) &&
		o.verifyCommitmentsOfAttrs(cr.CommitmentsOfAttrs, cr.CommitmentsOfAttrsProofs) &&
		o.verifyChallenge(cr.UProof.Challenge) &&
		o.verifyUProofDataLengths(cr.UProof.ProofData)
}

func (o *Org) verifyNym(proof *schnorr.Proof) bool {
	bases := []*big.Int{
		o.pedersenReceiver.Params.Group.G,
		o.pedersenReceiver.Params.H,
	}
	o.nymVerifier.SetProofRandomData(proof.ProofRandomData, bases, o.nym)
	o.nymVerifier.SetChallenge(proof.Challenge)

	return o.nymVerifier.Verify(proof.ProofData)
}

func (o *Org) verifyU(UProof *qr.RepresentationProof) bool {
	// bases are [R_1, ..., R_L, S]
	bases := append(o.PubKey.RsHidden, o.PubKey.S)
	o.UVerifier.SetProofRandomData(UProof.ProofRandomData, bases, o.U)
	o.UVerifier.SetChallenge(UProof.Challenge)

	return o.UVerifier.Verify(UProof.ProofData)
}

func (o *Org) setUpAttrVerifiers(commitmentsOfAttrs []*big.Int) error {
	attrsVerifiers := make([]*df.OpeningVerifier, len(commitmentsOfAttrs))
	for i, attr := range commitmentsOfAttrs {
		receiver, err := df.NewReceiverFromParams(
			o.SecKey.AttributesSpecialRSAPrimes, o.PubKey.G, o.PubKey.H, o.Params.SecParam)
		if err != nil {
			return err
		}
		receiver.SetCommitment(attr)

		verifier := df.NewOpeningVerifier(receiver, o.Params.ChallengeSpace)
		attrsVerifiers[i] = verifier
	}

	o.attrsVerifiers = attrsVerifiers
	o.commitmentsOfAttrs = commitmentsOfAttrs

	return nil
}

// commitments ... commitmentsOfAttrs
// proofs ... commitmentsOfAttrsProofs
func (o *Org) verifyCommitmentsOfAttrs(commitmentsOfAttrs []*big.Int, proofs []*df.OpeningProof) bool {
	//o.setUpAttrVerifiers(commitmentsOfAttrs)
	for i, v := range o.attrsVerifiers {
		v.SetProofRandomData(proofs[i].ProofRandomData)
		v.SetChallenge(proofs[i].Challenge)
		if !v.Verify(proofs[i].ProofData1, proofs[i].ProofData2) {
			return false
		}
	}

	return true
}

func (o *Org) verifyChallenge(challenge *big.Int) bool {
	context := o.PubKey.GetContext()
	l := []*big.Int{context, o.U, o.nym, o.credIssueNonceOrg}
	l = append(l, o.commitmentsOfAttrs...)
	c := common.Hash(l...)
	return c.Cmp(challenge) == 0
}

func (o *Org) verifyUProofDataLengths(UProofData []*big.Int) bool {
	// boundary for m_tilde
	b_m := o.Params.AttrBitLen + o.Params.SecParam + o.Params.HashBitLen + 2
	// boundary for v1_tilde
	b_v1 := o.Params.NLength + 2*o.Params.SecParam + o.Params.HashBitLen + 1

	exp := big.NewInt(int64(b_m))
	b1 := new(big.Int).Exp(big.NewInt(2), exp, nil)

	exp = big.NewInt(int64(b_v1))
	b2 := new(big.Int).Exp(big.NewInt(2), exp, nil)

	for ind := 0; ind < len(o.PubKey.RsHidden); ind++ {
		if UProofData[ind].Cmp(b1) > 0 {
			return false
		}
	}
	if UProofData[len(o.PubKey.RsHidden)].Cmp(b2) > 0 {
		return false
	}

	return true
}

type ReceiverRecord struct {
	KnownAttrs         []*big.Int
	CommitmentsOfAttrs []*big.Int
	Q                  *big.Int
	V11                *big.Int
	Context            *big.Int
}

// Returns ReceiverRecord which contains user data needed when updating the credential for this user.
func NewReceiverRecord(knownAttrs, commitmentsOfAttrs []*big.Int, Q, v11, context *big.Int) *ReceiverRecord {
	return &ReceiverRecord{
		KnownAttrs:         knownAttrs,
		CommitmentsOfAttrs: commitmentsOfAttrs,
		Q:                  Q,
		V11:                v11,
		Context:            context,
	}
}

func (r *ReceiverRecord) MarshalBinary() ([]byte, error) {
	return json.Marshal(r)
}

func (r *ReceiverRecord) UnmarshalBinary(data []byte) error {
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}

	return nil
}

// TODO: where should we put WriteGob and ReadGob?
func WriteGob(filePath string, object interface{}) error {
	file, err := os.Create(filePath)
	if err == nil {
		encoder := gob.NewEncoder(file)
		encoder.Encode(object)
	}
	file.Close()

	return err
}

func ReadGob(filePath string, object interface{}) error {
	file, err := os.Open(filePath)
	if err == nil {
		decoder := gob.NewDecoder(file)
		err = decoder.Decode(object)
	}
	file.Close()

	return err
}
