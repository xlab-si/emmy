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

package proto

import (
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/ec"
	"github.com/xlab-si/emmy/crypto/qr"
	"github.com/xlab-si/emmy/crypto/schnorr"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/commitments"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/cl"
)

type PbConvertibleType interface {
	GetNativeType() interface{}
}

func (el *ECGroupElement) GetNativeType() *ec.GroupElement {
	return &ec.GroupElement{
		X: new(big.Int).SetBytes(el.X),
		Y: new(big.Int).SetBytes(el.Y),
	}
}

func ToPbECGroupElement(el *ec.GroupElement) *ECGroupElement {
	x := ECGroupElement{X: el.X.Bytes(), Y: el.Y.Bytes()}
	return &x
}

func (el *Pair) GetNativeType() *common.Pair {
	return &common.Pair{
		A: new(big.Int).SetBytes(el.A),
		B: new(big.Int).SetBytes(el.B),
	}
}

func ToPbPair(el *common.Pair) *Pair {
	return &Pair{
		A: el.A.Bytes(),
		B: el.B.Bytes(),
	}
}

func ToPbCredentialRequest(r *cl.CredentialRequest) *CLCredReq {
	knownAttrs := make([][]byte, len(r.KnownAttrs))
	for i, a := range r.KnownAttrs {
		knownAttrs[i] = a.Bytes()
	}
	commitmentsOfAttrs := make([][]byte, len(r.CommitmentsOfAttrs))
	for i, a := range r.CommitmentsOfAttrs {
		commitmentsOfAttrs[i] = a.Bytes()
	}

	pData := make([][]byte, len(r.NymProof.ProofData))
	for i, p := range r.NymProof.ProofData {
		pData[i] = p.Bytes()
	}
	nymProof := &FiatShamir{
		ProofRandomData: r.NymProof.ProofRandomData.Bytes(),
		Challenge:       r.NymProof.Challenge.Bytes(),
		ProofData:       pData,
	}

	uData := make([]string, len(r.UProof.ProofData))
	for i, p := range r.UProof.ProofData {
		uData[i] = p.String()
	}
	UProof := &FiatShamirAlsoNeg{
		ProofRandomData: r.UProof.ProofRandomData.Bytes(),
		Challenge:       r.UProof.Challenge.Bytes(),
		ProofData:       uData,
	}

	proofs := make([]*FiatShamir, len(r.CommitmentsOfAttrsProofs))
	for i, proof := range r.CommitmentsOfAttrsProofs {
		pData = make([][]byte, 2)
		pData[0] = proof.ProofData1.Bytes()
		pData[1] = proof.ProofData2.Bytes()
		fs := &FiatShamir{
			ProofRandomData: proof.ProofRandomData.Bytes(),
			Challenge:       proof.Challenge.Bytes(),
			ProofData:       pData,
		}
		proofs[i] = fs
	}

	return &CLCredReq{
		Nym:                r.Nym.Bytes(),
		KnownAttrs:         knownAttrs,
		CommitmentsOfAttrs: commitmentsOfAttrs,
		NymProof:           nymProof,
		U:                  r.U.Bytes(),
		UProof:             UProof,
		CommitmentsOfAttrsProofs: proofs,
		Nonce: r.Nonce.Bytes(),
	}
}

func (r *CLCredReq) GetNativeType() (*cl.CredentialRequest, error) {
	nym := new(big.Int).SetBytes(r.Nym)
	knownAttrs := make([]*big.Int, len(r.KnownAttrs))
	for i, a := range r.KnownAttrs {
		knownAttrs[i] = new(big.Int).SetBytes(a)
	}
	commitmentsOfAttrs := make([]*big.Int, len(r.CommitmentsOfAttrs))
	for i, a := range r.CommitmentsOfAttrs {
		commitmentsOfAttrs[i] = new(big.Int).SetBytes(a)
	}

	pData := make([]*big.Int, len(r.NymProof.ProofData))
	for i, p := range r.NymProof.ProofData {
		pData[i] = new(big.Int).SetBytes(p)
	}
	nymProof := schnorr.NewProof(new(big.Int).SetBytes(r.NymProof.ProofRandomData),
		new(big.Int).SetBytes(r.NymProof.Challenge), pData)

	U := new(big.Int).SetBytes(r.U)

	pData = make([]*big.Int, len(r.UProof.ProofData))
	for i, p := range r.UProof.ProofData {
		si, success := new(big.Int).SetString(p, 10)
		if !success {
			return nil, fmt.Errorf("error when initializing big.Int from string")
		}
		pData[i] = si
	}
	UProof := qr.NewRepresentationProof(new(big.Int).SetBytes(r.UProof.ProofRandomData),
		new(big.Int).SetBytes(r.UProof.Challenge), pData)

	commitmentsOfAttrsProofs := make([]*commitmentzkp.DFOpeningProof, len(r.CommitmentsOfAttrsProofs))
	for i, proof := range r.CommitmentsOfAttrsProofs {
		openingProof := commitmentzkp.NewDFOpeningProof(new(big.Int).SetBytes(proof.ProofRandomData),
			new(big.Int).SetBytes(proof.Challenge), new(big.Int).SetBytes(proof.ProofData[0]),
			new(big.Int).SetBytes(proof.ProofData[1]))
		commitmentsOfAttrsProofs[i] = openingProof
	}

	return cl.NewCredentialRequest(nym, knownAttrs, commitmentsOfAttrs, nymProof, U, UProof,
		commitmentsOfAttrsProofs, new(big.Int).SetBytes(r.Nonce)), nil
}

func ToPbCLCredential(c *cl.Credential, AProof *qr.RepresentationProof) *CLCredential {
	AProofFS := &FiatShamirAlsoNeg{
		ProofRandomData: AProof.ProofRandomData.Bytes(),
		Challenge:       AProof.Challenge.Bytes(),
		ProofData:       []string{AProof.ProofData[0].String()},
	}

	return &CLCredential{
		A:      c.A.Bytes(),
		E:      c.E.Bytes(),
		V11:    c.V11.Bytes(),
		AProof: AProofFS,
	}
}

func (c *CLCredential) GetNativeType() (*cl.Credential, *qr.RepresentationProof, error) {
	si, success := new(big.Int).SetString(c.AProof.ProofData[0], 10)
	if !success {
		return nil, nil, fmt.Errorf("error when initializing big.Int from string")
	}

	AProof := qr.NewRepresentationProof(new(big.Int).SetBytes(c.AProof.ProofRandomData),
		new(big.Int).SetBytes(c.AProof.Challenge), []*big.Int{si})

	return cl.NewCredential(new(big.Int).SetBytes(c.A), new(big.Int).SetBytes(c.E),
		new(big.Int).SetBytes(c.V11)), AProof, nil
}

func ToPbUpdateCLCredential(nym, nonce *big.Int, newKnownAttrs []*big.Int) *UpdateCLCredential {
	knownAttrs := make([][]byte, len(newKnownAttrs))
	for i, a := range newKnownAttrs {
		knownAttrs[i] = a.Bytes()
	}

	return &UpdateCLCredential{
		Nym:           nym.Bytes(),
		Nonce:         nonce.Bytes(),
		NewKnownAttrs: knownAttrs,
	}
}

func (u *UpdateCLCredential) GetNativeType() (*big.Int, *big.Int, []*big.Int) {
	attrs := make([]*big.Int, len(u.NewKnownAttrs))
	for i, a := range u.NewKnownAttrs {
		attrs[i] = new(big.Int).SetBytes(a)
	}

	return new(big.Int).SetBytes(u.Nym), new(big.Int).SetBytes(u.Nonce), attrs
}

func ToPbProveCLCredential(A *big.Int, proof *qr.RepresentationProof,
	knownAttrs, commitmentsOfAttrs []*big.Int,
	revealedKnownAttrsIndices, revealedCommitmentsOfAttrsIndices []int) *ProveCLCredential {

	pData := make([]string, len(proof.ProofData))
	for i, p := range proof.ProofData {
		pData[i] = p.String()
	}
	proofFS := &FiatShamirAlsoNeg{
		ProofRandomData: proof.ProofRandomData.Bytes(),
		Challenge:       proof.Challenge.Bytes(),
		ProofData:       pData,
	}

	kAttrs := make([][]byte, len(knownAttrs))
	for i, a := range knownAttrs {
		kAttrs[i] = a.Bytes()
	}

	cAttrs := make([][]byte, len(commitmentsOfAttrs))
	for i, a := range commitmentsOfAttrs {
		cAttrs[i] = a.Bytes()
	}

	revealedKnownAttrs := make([]int32, len(revealedKnownAttrsIndices))
	for i, a := range revealedKnownAttrsIndices {
		revealedKnownAttrs[i] = int32(a)
	}

	revealedCommitmentsOfAttrs := make([]int32, len(revealedCommitmentsOfAttrsIndices))
	for i, a := range revealedCommitmentsOfAttrsIndices {
		revealedCommitmentsOfAttrs[i] = int32(a)
	}

	return &ProveCLCredential{
		A:                          A.Bytes(),
		Proof:                      proofFS,
		KnownAttrs:                 kAttrs,
		CommitmentsOfAttrs:         cAttrs,
		RevealedKnownAttrs:         revealedKnownAttrs,
		RevealedCommitmentsOfAttrs: revealedCommitmentsOfAttrs,
	}
}

func (p *ProveCLCredential) GetNativeType() (*big.Int, *qr.RepresentationProof, []*big.Int,
	[]*big.Int, []int, []int, error) {
	attrs := make([]*big.Int, len(p.KnownAttrs))
	for i, a := range p.KnownAttrs {
		attrs[i] = new(big.Int).SetBytes(a)
	}

	cAttrs := make([]*big.Int, len(p.CommitmentsOfAttrs))
	for i, a := range p.CommitmentsOfAttrs {
		cAttrs[i] = new(big.Int).SetBytes(a)
	}

	pData := make([]*big.Int, len(p.Proof.ProofData))
	for i, p := range p.Proof.ProofData {
		si, success := new(big.Int).SetString(p, 10)
		if !success {
			return nil, nil, nil, nil, nil, nil, fmt.Errorf("error when initializing big.Int from string")
		}
		pData[i] = si
	}
	proof := qr.NewRepresentationProof(new(big.Int).SetBytes(p.Proof.ProofRandomData),
		new(big.Int).SetBytes(p.Proof.Challenge), pData)

	revealedKnownAttrsIndices := make([]int, len(p.RevealedKnownAttrs))
	for i, a := range p.RevealedKnownAttrs {
		revealedKnownAttrsIndices[i] = int(a)
	}

	revealedCommitmentsOfAttrsIndices := make([]int, len(p.RevealedCommitmentsOfAttrs))
	for i, a := range p.RevealedCommitmentsOfAttrs {
		revealedCommitmentsOfAttrsIndices[i] = int(a)
	}

	return new(big.Int).SetBytes(p.A), proof, attrs, cAttrs, revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices, nil
}
