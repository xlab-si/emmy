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
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/commitments"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/cl"
)

type PbConvertibleType interface {
	GetNativeType() interface{}
}

func (el *ECGroupElement) GetNativeType() *groups.ECGroupElement {
	return &groups.ECGroupElement{
		X: new(big.Int).SetBytes(el.X),
		Y: new(big.Int).SetBytes(el.Y),
	}
}

func ToPbECGroupElement(el *groups.ECGroupElement) *ECGroupElement {
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
	nymProof := dlogproofs.NewSchnorrProof(new(big.Int).SetBytes(r.NymProof.ProofRandomData),
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
	UProof := qrspecialrsaproofs.NewRepresentationProof(new(big.Int).SetBytes(r.UProof.ProofRandomData),
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
